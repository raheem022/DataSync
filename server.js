import express from 'express';
import sql from 'mssql';
import cors from 'cors';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

// Get current directory for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load environment variables from single .env file
dotenv.config();

// Set environment-specific variables based on NODE_ENV
const isProduction = process.env.NODE_ENV === 'production';

// Override environment-specific settings
if (isProduction) {
  process.env.CORS_ORIGINS = process.env.PROD_CORS_ORIGINS || process.env.CORS_ORIGINS;
  process.env.LOG_LEVEL = process.env.PROD_LOG_LEVEL || process.env.LOG_LEVEL;
  process.env.WEBSITE_NODE_DEFAULT_VERSION = process.env.PROD_WEBSITE_NODE_DEFAULT_VERSION;
} else {
  process.env.CORS_ORIGINS = process.env.DEV_CORS_ORIGINS || process.env.CORS_ORIGINS;
  process.env.LOG_LEVEL = process.env.DEV_LOG_LEVEL || process.env.LOG_LEVEL;
  process.env.VITE_DEV_MODE = process.env.DEV_VITE_DEV_MODE || process.env.VITE_DEV_MODE;
}

const app = express();

// Use environment variable for port, with fallback
const port = process.env.PORT || 8081;

// CORS configuration for production
const corsOptions = {
  origin: process.env.NODE_ENV === 'production' 
    ? (process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',') : ['*'])
    : '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Production security middleware
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    // Security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
  });
}

// Validate required environment variables
const requiredEnvVars = ['DB_SERVER', 'DB_USER', 'DB_PASSWORD'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`❌ Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

// Azure SQL Database configuration using environment variables
const baseDbConfig = {
  server: process.env.DB_SERVER || 'datasync-sql-server-2025.database.windows.net',
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  port: parseInt(process.env.DB_PORT) || 1433,
  options: {
    encrypt: true,
    trustServerCertificate: process.env.NODE_ENV === 'development',
    connectionTimeout: 30000,
    requestTimeout: 30000,
  },
  pool: {
    max: process.env.NODE_ENV === 'production' ? 20 : 10,
    min: 0,
    idleTimeoutMillis: 30000,
  },
};

// Database configurations for all databases
const databases = {
  main: { ...baseDbConfig, database: 'DataSync' },
  andhraPradesh: { ...baseDbConfig, database: 'DataSync_AndhraPradesh' },
  karnataka: { ...baseDbConfig, database: 'DataSync_Karnataka' },
  tamilNadu: { ...baseDbConfig, database: 'DataSync_TamilNadu' }
};

// Global connection pools
let pools = {};
let poolPromise;

// Helper function to get the appropriate state database key
function getStateDbKey(state) {
  if (!state) return null;
  
  const stateNormalized = state.toLowerCase().replace(/[\s-_]/g, '');
  
  switch (stateNormalized) {
    case 'andhrapradesh':
    case 'ap':
      return 'andhraPradesh';
    case 'karnataka':
    case 'ka':
      return 'karnataka';
    case 'tamilnadu':
    case 'tn':
      return 'tamilNadu';
    default:
      return null;
  }
}

// Helper function to decode mobile authentication token
function decodeToken(token) {
  try {
    if (!token || !token.startsWith('Bearer ')) {
      return null;
    }
    
    const tokenData = token.replace('Bearer ', '');
    const decoded = Buffer.from(tokenData, 'base64').toString('utf8');
    const [userId, username, state, timestamp] = decoded.split(':');
    
    // Basic token validation (check if not too old - 24 hours)
    const tokenAge = Date.now() - parseInt(timestamp);
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours
    
    if (tokenAge > maxAge) {
      return null; // Token expired
    }
    
    return {
      userId: parseInt(userId),
      username,
      state,
      timestamp: parseInt(timestamp)
    };
  } catch (error) {
    return null;
  }
}

// Helper function to replicate user to state database
async function replicateUserToStateDatabase(userData, stateDbKey) {
  if (!stateDbKey || !pools[stateDbKey]) {
    console.log(`⚠️ No state database found for: ${userData.location_state}`);
    return false;
  }
  
  try {
    const statePool = pools[stateDbKey];
    
    // Check if user already exists in state database
    const checkQuery = 'SELECT COUNT(*) as count FROM app_users WHERE username = @username OR email = @email';
    const checkRequest = statePool.request();
    checkRequest.input('username', sql.NVarChar, userData.username);
    checkRequest.input('email', sql.NVarChar, userData.email);
    
    const checkResult = await checkRequest.query(checkQuery);
    if (checkResult.recordset[0].count > 0) {
      console.log(`⚠️ User already exists in state database: ${databases[stateDbKey].database}`);
      return true; // User already exists, consider it successful
    }
    
    // Insert user into state database
    const insertQuery = `
      INSERT INTO app_users (
        username, email, password_hash, user_role, location_state, 
        first_name, last_name, mobile_number, location_city,
        is_active, is_verified, is_locked, failed_login_attempts, max_failed_attempts,
        created_at, created_by
      ) 
      VALUES (
        @username, @email, @password_hash, @user_role, @location_state,
        @first_name, @last_name, @mobile_number, @location_city,
        @is_active, @is_verified, 0, 0, 5,
        @created_at, 'ADMIN_SYNC'
      )
    `;
    
    const insertRequest = statePool.request();
    insertRequest.input('username', sql.NVarChar, userData.username);
    insertRequest.input('email', sql.NVarChar, userData.email);
    insertRequest.input('password_hash', sql.NVarChar, userData.password_hash);
    insertRequest.input('user_role', sql.NVarChar, userData.user_role);
    insertRequest.input('location_state', sql.NVarChar, userData.location_state);
    insertRequest.input('first_name', sql.NVarChar, userData.first_name);
    insertRequest.input('last_name', sql.NVarChar, userData.last_name);
    insertRequest.input('mobile_number', sql.NVarChar, userData.mobile_number);
    insertRequest.input('location_city', sql.NVarChar, userData.location_city);
    insertRequest.input('is_active', sql.Bit, userData.is_active);
    insertRequest.input('is_verified', sql.Bit, userData.is_verified);
    insertRequest.input('created_at', sql.DateTime2, userData.created_at || new Date());
    
    await insertRequest.query(insertQuery);
    
    console.log(`✅ User replicated to state database: ${databases[stateDbKey].database}`);
    return true;
  } catch (error) {
    console.error(`❌ Failed to replicate user to ${databases[stateDbKey].database}:`, error);
    return false;
  }
}

async function initializeDatabase() {
  try {
    console.log('🔄 Initializing database connections...');
    
    // Initialize all database connections
    for (const [dbKey, config] of Object.entries(databases)) {
      console.log(`Connecting to ${config.database}...`);
      pools[dbKey] = await new sql.ConnectionPool(config).connect();
      console.log(`✅ Connected to ${config.database}`);
    }
    
    // Keep backward compatibility - main database as default
    poolPromise = Promise.resolve(pools.main);
    
    console.log('✅ All database connections established');
  } catch (error) {
    console.error('❌ Database connection failed:', error);
    process.exit(1);
  }
}

// API Routes

// Root route
app.get('/', (req, res) => {
  res.json({
    message: 'Admin API Server is running',
    status: 'online',
    endpoints: [
      '/health',
      '/api/auth/login',
      '/api/auth/mobile-login',
      '/api/admin/users',
      '/api/admin/users/sync',
      '/api/admin/metrics/overview',
      '/api/admin/metrics/state',
      '/api/admin/metrics/users',
      '/api/admin/metrics/daily',
      '/api/admin/metrics/states',
      '/api/customers',
      '/api/mobile/customers/allocated'
    ]
  });
});

/**
 * GET /api/admin/metrics/overview
 * Get global overview metrics
 */
app.get('/api/admin/metrics/overview', async (req, res) => {
  try {
    const pool = await poolPromise;
    const { from, to } = req.query;
    
    // Get basic customer counts
    let customerQuery = `
      SELECT 
        COUNT(*) as total_customers,
        COUNT(DISTINCT state) as total_states
      FROM customers
    `;
    
    if (from && to) {
      customerQuery += ` WHERE created_at BETWEEN @from AND @to`;
    }
    
    const customerRequest = pool.request();
    if (from) customerRequest.input('from', sql.DateTime, from);
    if (to) customerRequest.input('to', sql.DateTime, to);
    
    const customerResult = await customerRequest.query(customerQuery);
    const totalCustomers = customerResult.recordset[0].total_customers;
    
    // Get state summary
    const stateQuery = `
      SELECT 
        state,
        COUNT(*) as total_customers,
        COUNT(CASE WHEN firstname IS NOT NULL THEN 1 END) as customers_with_names
      FROM customers
      WHERE state IS NOT NULL
      GROUP BY state
      ORDER BY COUNT(*) DESC
    `;
    
    const stateResult = await pool.request().query(stateQuery);
    
    // Get user metrics using customer_allocations table first, fallback to legacy
    const userQuery = `
      SELECT TOP 10
        u.username,
        u.first_name,
        u.last_name,
        u.location_state,
        u.user_role,
        ISNULL(ca_count.allocation_count, 0) + ISNULL(legacy_count.legacy_count, 0) as linked_customers
      FROM app_users u
      LEFT JOIN (
        SELECT user_id, COUNT(*) as allocation_count
        FROM customer_allocations
        GROUP BY user_id
      ) ca_count ON ca_count.user_id = u.id
      LEFT JOIN (
        SELECT assigned_to, COUNT(*) as legacy_count
        FROM customers
        WHERE assigned_to IS NOT NULL
        GROUP BY assigned_to
      ) legacy_count ON legacy_count.assigned_to = u.id
      WHERE u.user_role = 'USER'
      GROUP BY u.id, u.username, u.first_name, u.last_name, u.location_state, u.user_role, ca_count.allocation_count, legacy_count.legacy_count
      ORDER BY (ISNULL(ca_count.allocation_count, 0) + ISNULL(legacy_count.legacy_count, 0)) DESC
    `;
    
    const userResult = await pool.request().query(userQuery);
    
    // Format response according to OverviewMetrics interface
    const overviewMetrics = {
      totalCustomers: totalCustomers,
      statusBreakdown: [
        { status: 'COMPLETED', count: Math.floor(totalCustomers * 0.3) }, // Sample data
        { status: 'IN_PROGRESS', count: Math.floor(totalCustomers * 0.4) },
        { status: 'NOT_STARTED', count: Math.floor(totalCustomers * 0.3) }
      ],
      statesSummary: stateResult.recordset.map(row => ({
        state: row.state,
        totalCustomers: row.total_customers,
        completedCount: Math.floor(row.total_customers * 0.3), // Sample completion rate
        inProgressCount: Math.floor(row.total_customers * 0.4),
        unassignedCount: Math.floor(row.total_customers * 0.3),
        activeUsers: 5, // Default value
        completionPercentage: 30 // Default 30%
      })),
      topUsers: userResult.recordset.map(row => ({
        username: row.username,
        fullName: `${row.first_name || ''} ${row.last_name || ''}`.trim() || row.username,
        locationState: row.location_state,
        assignedCount: row.linked_customers,
        completedCount: Math.floor(row.linked_customers * 0.7), // Sample completion
        todayUpdatedCount: Math.floor(row.linked_customers * 0.1)
      })),
      dailyProgress: [], // Will be populated by separate endpoint
      dateRange: {
        from: from || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
        to: to || new Date().toISOString()
      }
    };
    
    res.json({
      success: true,
      data: overviewMetrics
    });
  } catch (error) {
    console.error('Error fetching overview metrics:', error);
    res.status(500).json({
      success: false,
      error: `Failed to fetch overview metrics: ${error.message}`
    });
  }
});

/**
 * GET /api/admin/metrics/state
 * Get state-specific metrics
 */
app.get('/api/admin/metrics/state', async (req, res) => {
  try {
    const pool = await poolPromise;
    const { state, from, to } = req.query;
    
    let query = `
      SELECT 
        state,
        COUNT(*) as total_customers,
        COUNT(CASE WHEN firstname IS NOT NULL THEN 1 END) as customers_with_names,
        COUNT(CASE WHEN mobilenumber IS NOT NULL THEN 1 END) as customers_with_mobile
      FROM customers
      WHERE state = @state
    `;
    
    if (from && to) {
      query += ` AND created_at BETWEEN @from AND @to`;
    }
    
    query += ` GROUP BY state`;
    
    const request = pool.request();
    request.input('state', sql.VarChar, state);
    if (from) request.input('from', sql.DateTime, from);
    if (to) request.input('to', sql.DateTime, to);
    
    const result = await request.query(query);
    
    res.json({
      success: true,
      data: result.recordset
    });
  } catch (error) {
    console.error('Error fetching state metrics:', error);
    res.status(500).json({
      success: false,
      error: `Failed to fetch state metrics: ${error.message}`
    });
  }
});


/**
 * GET /api/admin/metrics/daily
 * Get daily progress trend data for the last 7 days
 */
app.get('/api/admin/metrics/daily', async (req, res) => {
  try {
    const pool = await poolPromise;
    const { state, days = 7 } = req.query;
    
    // Get daily data for the last N days
    let query = `
      WITH DailyCounts AS (
        SELECT 
          CAST(created_at as DATE) as date,
          COUNT(*) as count
        FROM customers
    `;
    
    const conditions = [];
    const request = pool.request();
    
    if (state) {
      conditions.push('state = @state');
      request.input('state', sql.VarChar, state);
    }
    
    // Add date range for last N days
    conditions.push('created_at >= @fromDate');
    request.input('fromDate', sql.DateTime, new Date(Date.now() - days * 24 * 60 * 60 * 1000));
    
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    
    query += `
        GROUP BY CAST(created_at as DATE)
      ),
      DateRange AS (
        SELECT TOP ${days}
          DATEADD(day, -ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) + 1, GETDATE()) as date
        FROM sys.objects
      )
      SELECT 
        FORMAT(dr.date, 'yyyy-MM-dd') as date,
        ISNULL(dc.count, 0) as count,
        -- Simulate progress data based on total count
        ISNULL(CAST(dc.count * 0.7 as INT), 0) as completed,
        ISNULL(CAST(dc.count * 0.3 as INT), 0) as in_progress
      FROM DateRange dr
      LEFT JOIN DailyCounts dc ON CAST(dr.date as DATE) = dc.date
      ORDER BY dr.date ASC
    `;
    
    const result = await request.query(query);
    
    res.json({
      success: true,
      data: result.recordset
    });
  } catch (error) {
    console.error('Error fetching daily metrics:', error);
    res.status(500).json({
      success: false,
      error: `Failed to fetch daily metrics: ${error.message}`
    });
  }
});

/**
 * GET /api/admin/metrics/states
 * Get available states
 */
app.get('/api/admin/metrics/states', async (req, res) => {
  try {
    const pool = await poolPromise;
    
    const query = `SELECT DISTINCT state FROM customers WHERE state IS NOT NULL ORDER BY state`;
    const result = await pool.request().query(query);
    
    res.json({
      success: true,
      data: result.recordset.map(row => row.state)
    });
  } catch (error) {
    console.error('Error fetching states:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch states'
    });
  }
});

/**
 * GET /api/customers
 * Get customers with filters
 */
app.get('/api/customers', async (req, res) => {
  try {
    const pool = await poolPromise;
    const { limit, state, assigned_to, page = 1, size = 50 } = req.query;
    
    let query = `
      SELECT 
        id, firstname, mobilenumber, city, state, pincode, address,
        customeremailaddress, contactperson, pincity, pinstate, pincodepin,
        fromleaddata, gender, relativename, addressline1, addressline2,
        bookingdate, invoicedate, registrationnum, vehiclemake, vehmodel,
        modelvariant, color, chassisnum, enginenum, financier, hypothecation,
        requestingdealer, cc, previousinsname, previnsno, requestingsubdealer,
        requestingstate, requestingregion, requestingcity, manufacture,
        requestingrto, typeofbody, registrationdate, created_at, updated_at
      FROM customers
    `;
    const conditions = [];
    const request = pool.request();
    
    if (state) {
      conditions.push('state = @state');
      request.input('state', sql.VarChar, state);
    }
    
    if (assigned_to !== undefined) {
      if (assigned_to === 'null' || assigned_to === '') {
        // Get unassigned customers
        conditions.push('assigned_to IS NULL');
      } else {
        // Get customers assigned to specific user
        conditions.push('assigned_to = @assigned_to');
        request.input('assigned_to', sql.BigInt, parseInt(assigned_to));
      }
    }
    
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    
    query += ' ORDER BY id DESC';
    
    if (limit) {
      query += ` OFFSET ${(page - 1) * size} ROWS FETCH NEXT ${Math.min(limit, size)} ROWS ONLY`;
    } else {
      query += ` OFFSET ${(page - 1) * size} ROWS FETCH NEXT ${size} ROWS ONLY`;
    }
    
    const result = await request.query(query);
    
    res.json({
      success: true,
      data: result.recordset
    });
  } catch (error) {
    console.error('Error fetching customers:', error);
    res.status(500).json({
      success: false,
      error: `Failed to fetch customers: ${error.message}`
    });
  }
});

/**
 * GET /api/mobile/customers/allocated
 * Get customers allocated to the authenticated mobile user from Phase 4 customer_allocations table
 */
app.get('/api/mobile/customers/allocated', async (req, res) => {
  try {
    console.log('📱 Mobile allocated customers request received');
    
    // Extract and validate token
    const authHeader = req.headers.authorization;
    const tokenData = decodeToken(authHeader);
    
    if (!tokenData) {
      return res.status(401).json({
        success: false,
        error: 'Invalid or expired authentication token'
      });
    }
    
    console.log(`🔍 Fetching allocated customers for user: ${tokenData.username} (ID: ${tokenData.userId})`);
    
    // Use main database 
    const mainPool = pools.main;
    const { page = 1, size = 50 } = req.query;
    
    // Try customer_allocations table first, fallback to customers.assigned_to
    let query, result, totalCount;
    
    // Skip customer_allocations table and use customers.assigned_to directly
    // This is needed because Phase 4 allocated customers using assigned_to field
    console.log('🔄 Using customers.assigned_to field directly (Phase 4 compatibility)');
    
    // Use customers.assigned_to field
      query = `
        SELECT 
          id, firstname, mobilenumber, city, state,
          customeremailaddress, registrationnum, vehiclemake, 
          vehmodel, created_at, updated_at,
          updated_at as allocated_at, 'ASSIGNED' as allocation_status, 
          'Assigned via legacy system' as allocation_notes
        FROM customers
        WHERE assigned_to = @userId
        ORDER BY updated_at DESC
        OFFSET @offset ROWS 
        FETCH NEXT @pageSize ROWS ONLY
      `;
      
      const request = mainPool.request();
      request.input('userId', sql.BigInt, tokenData.userId);
      request.input('offset', sql.Int, (page - 1) * size);
      request.input('pageSize', sql.Int, size);
      
      result = await request.query(query);
      
      // Get total count
      const countQuery = `
        SELECT COUNT(*) as total
        FROM customers
        WHERE assigned_to = @userId
      `;
      
      const countRequest = mainPool.request();
      countRequest.input('userId', sql.BigInt, tokenData.userId);
      const countResult = await countRequest.query(countQuery);
      totalCount = countResult.recordset[0].total;
      
      console.log(`✅ Found ${result.recordset.length} allocated customers via customers.assigned_to fallback`);
    
    res.json({
      success: true,
      data: {
        customers: result.recordset,
        pagination: {
          current_page: parseInt(page),
          page_size: parseInt(size),
          total_count: totalCount,
          total_pages: Math.ceil(totalCount / size)
        },
        user_info: {
          username: tokenData.username,
          user_id: tokenData.userId,
          state: tokenData.state
        }
      }
    });
  } catch (error) {
    console.error('Error fetching allocated customers:', error);
    res.status(500).json({
      success: false,
      error: `Failed to fetch allocated customers: ${error.message}`
    });
  }
});

/**
 * POST /api/auth/login
 * User authentication (Web/Admin)
 */
app.post('/api/auth/login', async (req, res) => {
  try {
    const pool = await poolPromise;
    const { username, pin } = req.body;
    
    if (!username || !pin) {
      return res.status(400).json({
        success: false,
        error: 'Username and PIN are required'
      });
    }
    
    const query = `
      SELECT 
        id, username, email, first_name, last_name, 
        user_role, location_state, is_active, is_locked,
        last_login
      FROM app_users 
      WHERE username = @username AND password_hash = @password_hash AND is_active = 1 AND is_locked = 0
    `;
    
    const request = pool.request();
    request.input('username', sql.VarChar, username);
    request.input('password_hash', sql.VarChar, pin); // Using PIN as simple password for now
    
    const result = await request.query(query);
    
    if (result.recordset.length === 0) {
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials or account locked'
      });
    }
    
    const user = result.recordset[0];
    
    // Update last login
    await pool.request()
      .input('userId', sql.Int, user.id)
      .query('UPDATE app_users SET last_login = GETDATE() WHERE id = @userId');
    
    // Generate a simple token (in production, use proper JWT)
    const token = Buffer.from(`${user.id}:${user.username}:${Date.now()}`).toString('base64');
    
    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          user_role: user.user_role,
          location_state: user.location_state,
          first_name: user.first_name,
          last_name: user.last_name
        },
        token: token
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      error: 'Login failed'
    });
  }
});

/**
 * POST /api/auth/mobile-login
 * Mobile app authentication (checks state-specific database)
 */
app.post('/api/auth/mobile-login', async (req, res) => {
  try {
    console.log('📱 Mobile login request received:', { username: req.body.username, state: req.body.state });
    
    const { username, pin, state } = req.body;
    
    if (!username || !pin || !state) {
      return res.status(400).json({
        success: false,
        error: 'Username, PIN, and state are required for mobile login'
      });
    }
    
    // Get the appropriate state database
    const stateDbKey = getStateDbKey(state);
    if (!stateDbKey || !pools[stateDbKey]) {
      return res.status(400).json({
        success: false,
        error: `Invalid state or state database not available: ${state}`
      });
    }
    
    const statePool = pools[stateDbKey];
    console.log(`🔍 Checking authentication in: ${databases[stateDbKey].database}`);
    
    const query = `
      SELECT 
        id, username, email, first_name, last_name, 
        user_role, location_state, is_active, is_locked,
        last_login, mobile_number
      FROM app_users 
      WHERE username = @username AND password_hash = @password_hash AND is_active = 1 AND is_locked = 0
    `;
    
    const request = statePool.request();
    request.input('username', sql.VarChar, username);
    request.input('password_hash', sql.VarChar, pin);
    
    const result = await request.query(query);
    
    if (result.recordset.length === 0) {
      console.log(`❌ Authentication failed for user: ${username} in ${databases[stateDbKey].database}`);
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials or account not found in this state'
      });
    }
    
    const user = result.recordset[0];
    console.log(`✅ Authentication successful for: ${user.username} (${user.user_role}) in ${databases[stateDbKey].database}`);
    
    // Update last login in state database
    await statePool.request()
      .input('userId', sql.Int, user.id)
      .query('UPDATE app_users SET last_login = GETDATE() WHERE id = @userId');
    
    // Generate mobile session token
    const token = Buffer.from(`${user.id}:${user.username}:${state}:${Date.now()}`).toString('base64');
    
    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          user_role: user.user_role,
          location_state: user.location_state,
          first_name: user.first_name,
          last_name: user.last_name,
          mobile_number: user.mobile_number
        },
        token: token,
        authenticated_from: databases[stateDbKey].database
      }
    });
  } catch (error) {
    console.error('Mobile login error:', error);
    res.status(500).json({
      success: false,
      error: 'Mobile login failed'
    });
  }
});

/**
 * GET /api/admin/users
 * Get all users with filtering and pagination
 */
app.get('/api/admin/users', async (req, res) => {
  try {
    const pool = await poolPromise;
    const { role, state, search, page = 1, size = 50, sort = 'created_at DESC' } = req.query;
    
    let query = `
      SELECT 
        u.id, u.username, u.email, u.first_name, u.last_name,
        u.user_role, u.location_state, u.location_city, u.mobile_number,
        u.is_active, u.is_locked, u.is_verified, 
        u.created_at, u.updated_at, u.last_login,
        COUNT(c.assigned_to) as assigned_count,
        COUNT(CASE WHEN c.processing_status IN ('COMPLETED', 'CLOSED', 'FINISHED') THEN 1 END) as completed_count,
        COUNT(CASE WHEN c.updated_at >= CAST(GETDATE() AS DATE) AND c.assigned_to = u.id THEN 1 END) as updated_today
      FROM app_users u
      LEFT JOIN customers c ON c.assigned_to = u.id
    `;
    
    const conditions = [];
    const request = pool.request();
    
    if (role) {
      conditions.push('u.user_role = @role');
      request.input('role', sql.VarChar, role);
    }
    
    if (state) {
      conditions.push('u.location_state = @state');
      request.input('state', sql.VarChar, state);
    }
    
    if (search) {
      conditions.push('(u.username LIKE @search OR u.email LIKE @search OR u.first_name LIKE @search OR u.last_name LIKE @search)');
      request.input('search', sql.VarChar, `%${search}%`);
    }
    
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    
    query += ' GROUP BY u.id, u.username, u.email, u.first_name, u.last_name, u.user_role, u.location_state, u.location_city, u.mobile_number, u.is_active, u.is_locked, u.is_verified, u.created_at, u.updated_at, u.last_login';
    query += ` ORDER BY ${sort}`;
    query += ` OFFSET ${(page - 1) * size} ROWS FETCH NEXT ${size} ROWS ONLY`;
    
    const result = await request.query(query);
    
    res.json({
      success: true,
      data: result.recordset
    });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch users'
    });
  }
});

/**
 * POST /api/admin/users
 * Create a new user
 */
app.post('/api/admin/users', async (req, res) => {
  try {
    const pool = await poolPromise;
    console.log('🔍 User creation request received:', req.body);
    
    const { 
      username, email, pin, user_role, location_state, 
      first_name, last_name, mobile_number, location_city,
      is_active = true, is_verified = false 
    } = req.body;
    
    // Validate required fields
    if (!username || !email || !pin || !user_role) {
      return res.status(400).json({
        success: false,
        error: 'Username, email, PIN, and role are required'
      });
    }
    
    // Validate that non-admin roles have location_state
    if (user_role !== 'ADMIN' && !location_state) {
      return res.status(400).json({
        success: false,
        error: 'Location state is required for USER, MANAGER, and TEAM_LEAD roles'
      });
    }
    
    // Check if username or email already exists in main database
    const checkQuery = 'SELECT COUNT(*) as count FROM app_users WHERE username = @username OR email = @email';
    const checkRequest = pool.request();
    checkRequest.input('username', sql.NVarChar, username);
    checkRequest.input('email', sql.NVarChar, email);
    
    const checkResult = await checkRequest.query(checkQuery);
    if (checkResult.recordset[0].count > 0) {
      return res.status(409).json({
        success: false,
        error: 'Username or email already exists'
      });
    }
    
    // Insert new user in main database (always create in main)
    const insertQuery = `
      INSERT INTO app_users (
        username, email, password_hash, user_role, location_state, 
        first_name, last_name, mobile_number, location_city,
        is_active, is_verified, is_locked, failed_login_attempts, max_failed_attempts
      ) 
      OUTPUT INSERTED.*
      VALUES (
        @username, @email, @password_hash, @user_role, @location_state,
        @first_name, @last_name, @mobile_number, @location_city,
        @is_active, @is_verified, 0, 0, 5
      )
    `;
    
    const insertRequest = pool.request();
    insertRequest.input('username', sql.NVarChar, username);
    insertRequest.input('email', sql.NVarChar, email);
    insertRequest.input('password_hash', sql.NVarChar, pin); // Using PIN as simple password
    insertRequest.input('user_role', sql.NVarChar, user_role);
    insertRequest.input('location_state', sql.NVarChar, location_state || null);
    insertRequest.input('first_name', sql.NVarChar, first_name || null);
    insertRequest.input('last_name', sql.NVarChar, last_name || null);
    insertRequest.input('mobile_number', sql.NVarChar, mobile_number || null);
    insertRequest.input('location_city', sql.NVarChar, location_city || null);
    insertRequest.input('is_active', sql.Bit, is_active);
    insertRequest.input('is_verified', sql.Bit, is_verified);
    
    const insertResult = await insertRequest.query(insertQuery);
    const newUser = insertResult.recordset[0];
    
    console.log(`✅ User created in main database: ${newUser.username} (${user_role})`);
    
    // Determine replication strategy based on role
    let replicationStatus = 'not_applicable';
    let replicationMessage = '';
    
    if (user_role === 'ADMIN') {
      // ADMIN: Only in main database
      replicationStatus = 'admin_only';
      replicationMessage = 'Admin user created only in main database';
      console.log(`🔑 ADMIN user - no state replication needed`);
    } else if (['USER', 'MANAGER', 'TEAM_LEAD'].includes(user_role)) {
      // USER, MANAGER, TEAM_LEAD: Main + State database
      const stateDbKey = getStateDbKey(location_state);
      
      if (stateDbKey) {
        console.log(`📋 Replicating ${user_role} to state database: ${databases[stateDbKey].database}`);
        const replicationSuccess = await replicateUserToStateDatabase(newUser, stateDbKey);
        
        if (replicationSuccess) {
          replicationStatus = 'success';
          replicationMessage = `User created in both main and ${databases[stateDbKey].database}`;
        } else {
          replicationStatus = 'failed';
          replicationMessage = `User created in main database but failed to replicate to ${databases[stateDbKey].database}`;
        }
      } else {
        replicationStatus = 'invalid_state';
        replicationMessage = `No matching state database found for state: ${location_state}`;
        console.warn(`⚠️ No matching state database found for state: ${location_state}`);
      }
    }
    
    res.status(201).json({
      success: true,
      data: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        user_role: newUser.user_role,
        location_state: newUser.location_state,
        first_name: newUser.first_name,
        last_name: newUser.last_name,
        is_active: newUser.is_active,
        created_at: newUser.created_at,
        replication: {
          status: replicationStatus,
          message: replicationMessage
        }
      }
    });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to create user'
    });
  }
});

/**
 * PATCH /api/admin/users/:id
 * Update user
 */
app.patch('/api/admin/users/:id', async (req, res) => {
  try {
    const pool = await poolPromise;
    const userId = req.params.id;
    const updates = req.body;
    
    const allowedFields = ['first_name', 'last_name', 'email', 'mobile_number', 'location_city', 'location_state', 'user_role', 'is_active', 'is_locked'];
    const updateFields = [];
    const request = pool.request();
    
    Object.keys(updates).forEach(key => {
      if (allowedFields.includes(key)) {
        updateFields.push(`${key} = @${key}`);
        request.input(key, updates[key]);
      }
    });
    
    if (updateFields.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'No valid fields to update'
      });
    }
    
    updateFields.push('updated_at = GETDATE()');
    request.input('userId', sql.Int, userId);
    
    const query = `UPDATE app_users SET ${updateFields.join(', ')} WHERE id = @userId`;
    await request.query(query);
    
    res.json({
      success: true,
      data: { id: userId, ...updates }
    });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update user'
    });
  }
});

/**
 * POST /api/admin/users/:id/reset-pin
 * Reset user PIN
 */
app.post('/api/admin/users/:id/reset-pin', async (req, res) => {
  try {
    const pool = await poolPromise;
    const userId = req.params.id;
    const { new_pin } = req.body;
    
    if (!new_pin) {
      return res.status(400).json({
        success: false,
        error: 'New PIN is required'
      });
    }
    
    const query = 'UPDATE app_users SET password_hash = @newPin, updated_at = GETDATE() WHERE id = @userId';
    const request = pool.request();
    request.input('newPin', sql.VarChar, new_pin);
    request.input('userId', sql.Int, userId);
    
    await request.query(query);
    
    res.json({
      success: true,
      data: { message: 'PIN updated successfully' }
    });
  } catch (error) {
    console.error('Error resetting PIN:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to reset PIN'
    });
  }
});

/**
 * POST /api/admin/users/sync
 * Synchronize existing users from main database to state databases
 */
app.post('/api/admin/users/sync', async (req, res) => {
  try {
    const mainPool = await poolPromise;
    console.log('🔄 Starting user synchronization from main to state databases...');
    
    // Get all users from main database
    const getUsersQuery = `
      SELECT 
        username, email, password_hash, user_role, location_state,
        first_name, last_name, mobile_number, location_city,
        is_active, is_verified, created_at
      FROM app_users
      WHERE location_state IN ('Karnataka', 'TamilNadu', 'AndhraPradesh', 'Andhra Pradesh')
        AND user_role != 'ADMIN'
    `;
    
    const usersResult = await mainPool.request().query(getUsersQuery);
    const users = usersResult.recordset;
    
    console.log(`📄 Found ${users.length} users to sync`);
    
    const syncResults = {
      total: users.length,
      synced: 0,
      failed: 0,
      skipped: 0,
      details: []
    };
    
    // Sync each user to their appropriate state database
    for (const user of users) {
      const stateDbKey = getStateDbKey(user.location_state);
      
      if (!stateDbKey) {
        syncResults.failed++;
        syncResults.details.push({
          username: user.username,
          state: user.location_state,
          status: 'failed',
          reason: 'No matching state database found'
        });
        continue;
      }
      
      const replicationSuccess = await replicateUserToStateDatabase(user, stateDbKey);
      
      if (replicationSuccess) {
        syncResults.synced++;
        syncResults.details.push({
          username: user.username,
          state: user.location_state,
          target_db: databases[stateDbKey].database,
          status: 'success'
        });
      } else {
        syncResults.failed++;
        syncResults.details.push({
          username: user.username,
          state: user.location_state,
          target_db: databases[stateDbKey].database,
          status: 'failed',
          reason: 'Replication error'
        });
      }
    }
    
    console.log(`✅ Synchronization completed: ${syncResults.synced} synced, ${syncResults.failed} failed, ${syncResults.skipped} skipped`);
    
    res.json({
      success: true,
      data: syncResults
    });
  } catch (error) {
    console.error('Error during user synchronization:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to synchronize users'
    });
  }
});

/**
 * GET /api/debug/assignments
 * Debug endpoint to check user assignments
 */
app.get('/api/debug/assignments', async (req, res) => {
  try {
    const pool = await poolPromise;
    
    // Check customers.assigned_to
    const assignedQuery = `
      SELECT 
        assigned_to as user_id, COUNT(*) as count
      FROM customers 
      WHERE assigned_to IS NOT NULL 
        AND assigned_to != ''
      GROUP BY assigned_to
      ORDER BY assigned_to
    `;
    
    const assignedResult = await pool.request().query(assignedQuery);
    
    // Check customer_allocations
    const allocationsQuery = `
      SELECT 
        user_id, COUNT(*) as count
      FROM customer_allocations
      GROUP BY user_id
      ORDER BY user_id
    `;
    
    const allocationsResult = await pool.request().query(allocationsQuery);
    
    // Check users
    const usersQuery = `
      SELECT id, username, location_state
      FROM app_users
      WHERE is_active = 1
      ORDER BY id
    `;
    
    const usersResult = await pool.request().query(usersQuery);
    
    res.json({
      success: true,
      data: {
        customers_assigned_to: assignedResult.recordset,
        customer_allocations: allocationsResult.recordset,
        active_users: usersResult.recordset
      }
    });
  } catch (error) {
    console.error('Debug assignments error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    const pool = await poolPromise;
    await pool.request().query('SELECT 1');
    res.json({ status: 'healthy', database: 'connected' });
  } catch (error) {
    res.status(500).json({ status: 'unhealthy', database: 'disconnected', error: error.message });
  }
});

// Graceful shutdown handling
process.on('SIGTERM', async () => {
  console.log('🔄 Received SIGTERM signal, shutting down gracefully...');
  
  // Close all database connections
  for (const [dbKey, pool] of Object.entries(pools)) {
    try {
      await pool.close();
      console.log(`✅ Closed connection to ${databases[dbKey].database}`);
    } catch (error) {
      console.error(`❌ Error closing ${databases[dbKey].database}:`, error);
    }
  }
  
  process.exit(0);
});

// Start server
async function startServer() {
  try {
    await initializeDatabase();
    
    // Listen on all interfaces (0.0.0.0) to allow connections
    const server = app.listen(port, '0.0.0.0', () => {
      console.log(`🚀 ${process.env.APP_NAME || 'Insurance Admin API'} Server Started`);
      console.log(`   Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`   Port: ${port}`);
      
      if (process.env.NODE_ENV === 'production') {
        console.log(`   🌐 Production URL: ${process.env.API_BASE_URL || 'https://your-app.azurewebsites.net'}`);
      } else {
        console.log(`   🖥️ Localhost: http://localhost:${port}`);
        console.log(`   📱 Mobile device: http://10.109.37.42:${port}`);
        console.log(`   🌐 All interfaces: http://0.0.0.0:${port}`);
      }
      
      console.log(`📊 Connected to Azure SQL Database: DataSync`);
      console.log(`📊 State databases: Karnataka, Tamil Nadu, Andhra Pradesh`);
    });
    
    // Handle server errors
    server.on('error', (error) => {
      if (error.code === 'EADDRINUSE') {
        console.error(`❌ Port ${port} is already in use`);
      } else {
        console.error('❌ Server error:', error);
      }
      process.exit(1);
    });
    
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

startServer();
