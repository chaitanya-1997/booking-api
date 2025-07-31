

const express = require('express');
const { pool } = require('./dbConfig');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const cron = require('node-cron');
const multer = require('multer');
const path = require('path');

const app = express();
const port = 3000;

app.use(cors({ origin: '*' })); // Allow all origins for testing
app.use(express.json());


// Storage configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, 'uploads/profile-photos'));
  },
  filename: function (req, file, cb) {
    // Save with user id and timestamp to avoid conflicts
    const ext = path.extname(file.originalname);
    cb(null, 'user_' + req.user.UserID + '_' + Date.now() + ext);
  }
});

const upload = multer({ storage });



// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    req.user = decoded; // { UserID, Email, Role }
    next();
  } catch (err) {
    console.error('Token verification error:', err);
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};


const authenticateAdmin = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    req.admin = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// Example: Ensure req.admin.role === 'superadmin'
const authenticateSuperAdmin = (req, res, next) => {
  try {

    if (req.admin.role !== 'superadmin') {
      return res.status(403).json({ error: 'Forbidden: Superadmin access required' });
    }
    next();
  } catch (err) {
    console.error('SuperAdmin auth error:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
};



// Create Notification Function




const createNotification = async (userId, recipientId, type, message) => {
  try {
    console.log('Creating notification:', { userId, recipientId, type, message });
    await pool.query(
      'INSERT INTO Notifications (UserID, RecipientID, Type, Message, IsRead) VALUES (?, ?, ?, ?, ?)',
      [userId || null, recipientId || null, type, message, false]
    );
    console.log('Notification created successfully');
  } catch (err) {
    console.error('Error creating notification:', err);
    throw err; // Rethrow to catch in caller
  }
};

// Login API
app.post('/login', async (req, res) => {
  try {
    console.log('Received body:', req.body);
    const { Email, Password } = req.body;
    if (!Email || !Password) {
      return res.status(400).json({ error: 'Email and Password are required' });
    }
    const [users] = await pool.query('SELECT * FROM Users WHERE Email = ? AND IsActive = 1', [Email]);
    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = users[0];
    const isMatch = await bcrypt.compare(Password, user.PasswordHash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign(
      { UserID: user.UserID, Email: user.Email, Role: user.Role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );
    res.json({
      message: 'Login successful',
      token,
      user: { UserID: user.UserID, FullName: user.FullName, Email: user.Email, Role: user.Role },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Signup API
app.post('/signup', async (req, res) => {
  try {
    console.log('Received body:', req.body);
    const { FullName, Email, Password, Phone, Department, Role } = req.body;
    if (!FullName || !Email || !Password) {
      return res.status(400).json({ error: 'FullName, Email, and Password are required' });
    }
    const [existing] = await pool.query('SELECT Email FROM Users WHERE Email = ?', [Email]);
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    const PasswordHash = await bcrypt.hash(Password, 10);
    await pool.query(
      'INSERT INTO Users (FullName, Email, PasswordHash, Phone, Department, Role) VALUES (?, ?, ?, ?, ?, ?)',
      [FullName, Email, PasswordHash, Phone || null, Department || null, Role || 'User']
    );
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error('Sign-up error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all users (for testing)
app.get('/users', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT UserID, FullName, Email, Role, CreatedAt, IsActive FROM Users');
    res.json(rows);
  } catch (err) {
    console.error('Query error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Protected route: Fetch user-specific data
// app.get('/user-data', authenticateToken, async (req, res) => {
//   try {
//     const userId = req.user.UserID; // From decoded JWT
//     console.log('Fetching data for UserID:', userId);
//     const [rows] = await pool.query('SELECT FullName, Email, Phone, Department FROM Users WHERE UserID = ?', [userId]);
//     if (rows.length === 0) {
//       return res.status(404).json({ error: 'User not found' });
//     }
//     res.json({
//       someData: `Data for user ${rows[0].FullName}`,
//       user: rows[0],
//     });
//   } catch (err) {
//     console.error('User data error:', err);
//     res.status(500).json({ error: 'Server error' });
//   }
// });

app.get('/user-data', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.UserID;
    const [rows] = await pool.query(
      'SELECT FullName, Email, Phone, Department, ProfilePhoto FROM Users WHERE UserID = ?',
      [userId]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ user: rows[0] });
  } catch (err) {
    console.error('User data error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});



// Update user profile
// app.put('/update-profile', authenticateToken, async (req, res) => {
//   try {
//     console.log('Received body:', req.body);
//     const userId = req.user.UserID;
//     const { FullName, Email, Phone, Department } = req.body;
//     if (!FullName || !Email) {
//       return res.status(400).json({ error: 'FullName and Email are required' });
//     }
//     const [existing] = await pool.query('SELECT Email FROM Users WHERE Email = ? AND UserID != ?', [Email, userId]);
//     if (existing.length > 0) {
//       return res.status(400).json({ error: 'Email already registered by another user' });
//     }
//     await pool.query(
//       'UPDATE Users SET FullName = ?, Email = ?, Phone = ?, Department = ? WHERE UserID = ?',
//       [FullName, Email, Phone || null, Department || null, userId]
//     );
//     res.json({ message: 'Profile updated successfully' });
//   } catch (err) {
//     console.error('Update profile error:', err);
//     res.status(500).json({ error: 'Server error' });
//   }
// });

app.put('/update-profile', authenticateToken, upload.single('profilePhoto'), async (req, res) => {
  try {
    const userId = req.user.UserID;
    const { FullName, Email, Phone, Department } = req.body;
    let profilePhotoPath = null;

    if (!FullName || !Email) {
      return res.status(400).json({ error: 'FullName and Email are required' });
    }

    // If file uploaded, store path relative to public dir (e.g., 'uploads/profile-photos/filename.jpg')
    if (req.file) {
      profilePhotoPath = `uploads/profile-photos/${req.file.filename}`;
    }

    // Check for existing email
    const [existing] = await pool.query(
      'SELECT Email FROM Users WHERE Email = ? AND UserID != ?',
      [Email, userId]
    );
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Email already registered by another user' });
    }

    // Update with photo if present
    if (profilePhotoPath) {
      await pool.query(
        'UPDATE Users SET FullName = ?, Email = ?, Phone = ?, Department = ?, ProfilePhoto = ? WHERE UserID = ?',
        [FullName, Email, Phone || null, Department || null, profilePhotoPath, userId]
      );
    } else {
      await pool.query(
        'UPDATE Users SET FullName = ?, Email = ?, Phone = ?, Department = ? WHERE UserID = ?',
        [FullName, Email, Phone || null, Department || null, userId]
      );
    }

    res.json({ message: 'Profile updated successfully', profilePhoto: profilePhotoPath });
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});




app.get('/rooms', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT RoomID AS id, Name AS name, Capacity AS capacity, Products AS products FROM Rooms WHERE IsActive = 1');
    const rooms = rows.map(row => ({
      ...row,
      products: row.products ? row.products.split(',') : [],
    }));
    res.json(rooms);
  } catch (err) {
    console.error('Rooms error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});


app.get('/slots', async (req, res) => {
  try {
    const { date, roomId } = req.query;
    if (!date || !roomId) {
      return res.status(400).json({ error: 'Date and roomId are required' });
    }
    const [allSlots] = await pool.query('SELECT SlotID AS id, StartTime AS startTime, EndTime AS endTime, Display AS display FROM TimeSlots');
    const [bookedSlots] = await pool.query(
      'SELECT SlotID FROM Bookings WHERE BookingDate = ? AND RoomID = ? AND Status != "Cancelled"',
      [date, roomId]
    );
    const bookedSlotIds = bookedSlots.map(slot => slot.SlotID);
    const slots = allSlots.map(slot => ({
      ...slot,
      available: !bookedSlotIds.includes(slot.id),
    }));
    res.json(slots);
  } catch (err) {
    console.error('Slots error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/bookings', authenticateToken, async (req, res) => {
  try {
    console.log('Received body:', req.body);
    const userId = req.user.UserID;
    const { roomId, slotId, date, reason } = req.body;
    if (!roomId || !slotId || !date || !reason ) {
      return res.status(400).json({ error: 'roomId, slotId, date, reason, and department are required' });
    }
    const [existing] = await pool.query(
      'SELECT BookingID FROM Bookings WHERE RoomID = ? AND SlotID = ? AND BookingDate = ? AND Status != "Cancelled"',
      [roomId, slotId, date]
    );
    if (existing.length > 0) {
      return res.status(409).json({ error: 'This slot is already booked' });
    }

     const [adminexisting] = await pool.query(
      'SELECT BookingID FROM Admin_Booking WHERE RoomID = ? AND SlotID = ? AND BookingDate = ? AND Status != "Cancelled"',
      [roomId, slotId, date]
    );
    if (adminexisting.length > 0) {
      return res.status(409).json({ error: 'This slot is already booked' });
    }
    // Verify room, slot, and user exist
    const [room] = await pool.query('SELECT Name FROM Rooms WHERE RoomID = ?', [roomId]);
    const [slot] = await pool.query('SELECT Display FROM TimeSlots WHERE SlotID = ?', [slotId]);
    const [user] = await pool.query('SELECT FullName FROM Users WHERE UserID = ?', [userId]);
    if (!room.length || !slot.length || !user.length) {
      return res.status(404).json({ error: 'Room, slot, or user not found' });
    }
    // Create booking
    await pool.query(
      'INSERT INTO Bookings (UserID, RoomID, SlotID, BookingDate, Reason, Status, Department) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [userId, roomId, slotId, date, reason, 'Confirmed', 'development']
    );
    // Create notification
    const message = `${user[0].FullName} booked ${room[0].Name} for ${slot[0].Display} on ${date}.`;
    console.log('Attempting to create notification:', { userId, message });
    await createNotification(userId, null, 'BOOKING_CREATED', message);
    res.status(201).json({ message: 'Booking created successfully' });
  } catch (err) {
    console.error('Booking error:', err);
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'This slot is already booked' });
    }
    res.status(500).json({ error: 'Server error' });
  }
});


app.post('/bookingsuser', authenticateToken, async (req, res) => {
  try {
    console.log('Received body:', req.body);
    const userId = req.user.UserID;
    const { roomId, slotId, date, reason } = req.body;
    if (!roomId || !slotId || !date || !reason) {
      return res.status(400).json({ error: 'roomId, slotId, date, and reason are required' });
    }
    const [existing] = await pool.query(
      'SELECT BookingID FROM Bookings WHERE RoomID = ? AND SlotID = ? AND BookingDate = ? AND Status != "Cancelled"',
      [roomId, slotId, date]
    );
    if (existing.length > 0) {
      return res.status(409).json({ error: 'This slot is already booked' });
    }

 const [adminexisting] = await pool.query(
      'SELECT BookingID FROM Admin_Booking WHERE RoomID = ? AND SlotID = ? AND BookingDate = ? AND Status != "Cancelled"',
      [roomId, slotId, date]
    );
    if (adminexisting.length > 0) {
      return res.status(409).json({ error: 'This slot is already booked' });
    }

    // Verify room, slot, and user exist
    const [room] = await pool.query('SELECT Name FROM Rooms WHERE RoomID = ?', [roomId]);
    const [slot] = await pool.query('SELECT Display FROM TimeSlots WHERE SlotID = ?', [slotId]);
    const [user] = await pool.query('SELECT FullName, Department FROM Users WHERE UserID = ?', [userId]);
    if (!room.length || !slot.length || !user.length) {
      return res.status(404).json({ error: 'Room, slot, or user not found' });
    }
    // Use user[0].Department for department, or set as null if you don't want to save
    await pool.query(
      'INSERT INTO Bookings (UserID, RoomID, SlotID, BookingDate, Reason, Status, Department) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [userId, roomId, slotId, date, reason, 'Confirmed', user[0].Department ?? null]
    );
    // Create notification
    const message = `${user[0].FullName} booked ${room[0].Name} for ${slot[0].Display} on ${date}.`;
    await createNotification(userId, null, 'BOOKING_CREATED', message);
    res.status(201).json({ message: 'Booking created successfully' });
  } catch (err) {
    console.error('Booking error:', err);
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'This slot is already booked' });
    }
    res.status(500).json({ error: 'Server error' });
  }
});



// app.get('/bookings', authenticateToken, async (req, res) => {
//   try {
//     const userId = req.user.UserID;
//     const [rows] = await pool.query(
//       `SELECT 
//          b.BookingID AS id, 
//          u.FullName AS name,
//          COALESCE(r.Name, 'Unknown Room') AS room, 
//          b.BookingDate AS date, 
//          t.Display AS time, 
//          b.Reason AS reason, 
//          b.Status AS status, 
//          b.Department AS department, 
//          r.Products AS products
//        FROM Bookings b
//        JOIN Rooms r ON b.RoomID = r.RoomID
//        JOIN TimeSlots t ON b.SlotID = t.SlotID
//        JOIN Users u ON b.UserID = u.UserID
//        WHERE b.UserID = ? AND b.Status != 'Cancelled'`,
//       [userId]
//     );
//     const bookings = rows.map(row => ({
//       ...row,
//       products: row.products ? row.products.split(',') : [],
//     }));
//     res.json(bookings);
//   } catch (err) {
//     console.error('Bookings error:', err);
//     res.status(500).json({ error: 'Server error' });
//   }
// });

app.get('/bookings', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.UserID;
    const [rows] = await pool.query(
      `SELECT 
         b.BookingID AS id, 
         u.FullName AS name,
         COALESCE(r.Name, 'Unknown Room') AS room, 
         b.BookingDate AS date, 
         t.Display AS time, 
         b.Reason AS reason, 
         b.Status AS status, 
         b.Department AS department, 
         r.Products AS products
       FROM Bookings b
       JOIN Rooms r ON b.RoomID = r.RoomID
       JOIN TimeSlots t ON b.SlotID = t.SlotID
       JOIN Users u ON b.UserID = u.UserID
       WHERE b.UserID = ?
       ORDER BY b.BookingDate DESC, t.StartTime ASC
      `,
      [userId]
    );
    const bookings = rows.map(row => ({
      ...row,
      products: row.products ? row.products.split(',') : [],
    }));
    res.json(bookings);
  } catch (err) {
    console.error('Bookings error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});



app.get('/admin/bookings', authenticateToken, async (req, res) => {
  try {
    if (req.user.Role !== 'Admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    const [rows] = await pool.query(
      `SELECT 
         b.BookingID AS id, 
         u.FullName AS name, 
         u.Department AS userDepartment, 
         r.Name AS room, 
         b.BookingDate AS date, 
         t.Display AS time, 
         b.Reason AS reason, 
         b.Status AS status, 
         r.Products AS products
       FROM Bookings b
       JOIN Users u ON b.UserID = u.UserID
       JOIN Rooms r ON b.RoomID = r.RoomID
       JOIN TimeSlots t ON b.SlotID = t.SlotID
       WHERE b.Status != 'Cancelled'`
    );
    const bookings = rows.map(row => ({
      ...row,
      products: row.products ? row.products.split(',') : [],
    }));
    res.json(bookings);
  } catch (err) {
    console.error('Admin bookings error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/bookings/:id', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.UserID;
    const bookingId = req.params.id;
    // Fetch booking details for notification
    const [booking] = await pool.query(
      `SELECT b.*, u.FullName, r.Name AS RoomName, t.Display AS SlotDisplay
       FROM Bookings b
       JOIN Users u ON b.UserID = u.UserID
       JOIN Rooms r ON b.RoomID = r.RoomID
       JOIN TimeSlots t ON b.SlotID = t.SlotID
       WHERE b.BookingID = ? AND b.UserID = ? AND b.Status != 'Cancelled'`,
      [bookingId, userId]
    );
    if (!booking.length) {
      return res.status(404).json({ error: 'Booking not found or not authorized' });
    }
    // Cancel booking
    const [result] = await pool.query(
      'UPDATE Bookings SET Status = "Cancelled" WHERE BookingID = ? AND UserID = ? AND Status != "Cancelled"',
      [bookingId, userId]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Booking not found or not authorized' });
    }
    // Create notification
    const message = `${booking[0].FullName} cancelled a booking for ${booking[0].RoomName} at ${booking[0].SlotDisplay} on ${booking[0].BookingDate}.`;
    console.log('Attempting to create notification:', { userId, message });
    await createNotification(userId, null, 'BOOKING_CANCELLED', message);
    res.json({ message: 'Booking cancelled successfully' });
  } catch (err) {
    console.error('Cancel booking error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});


app.put('/bookings/:id', authenticateToken, async (req, res) => {
  try {
    console.log('Received body:', req.body);
    const userId = req.user.UserID;
    const bookingId = req.params.id;
    const { roomId, slotId, date, reason } = req.body;

    if (!roomId || !slotId || !date || !reason) {
      return res.status(400).json({ error: 'roomId, slotId, date, reason,  are required' });
    }

    // Validate roomId (integer or room name)
    let parsedRoomId;
    const isNumericRoomId = !isNaN(parseInt(roomId, 10));
    if (isNumericRoomId) {
      parsedRoomId = parseInt(roomId, 10);
    } else {
      // Try to find RoomID by Name
      const [roomByName] = await pool.query('SELECT RoomID, Name FROM Rooms WHERE Name = ?', [roomId]);
      if (!roomByName.length) {
        return res.status(400).json({ error: 'Invalid roomId: Room does not exist' });
      }
      parsedRoomId = roomByName[0].RoomID;
    }

    // Validate slotId
    const parsedSlotId = parseInt(slotId, 10);
    if (isNaN(parsedSlotId)) {
      return res.status(400).json({ error: 'slotId must be a valid integer' });
    }

    // Verify room, slot, and user exist
    const [room] = await pool.query('SELECT Name FROM Rooms WHERE RoomID = ?', [parsedRoomId]);
    const [slot] = await pool.query('SELECT Display FROM TimeSlots WHERE SlotID = ?', [parsedSlotId]);
    const [user] = await pool.query('SELECT FullName FROM Users WHERE UserID = ?', [userId]);
    if (!room.length || !slot.length || !user.length) {
      return res.status(404).json({ error: 'Room, slot, or user not found' });
    }

    // Verify booking exists and belongs to user
    const [bookings] = await pool.query(
      'SELECT * FROM Bookings WHERE BookingID = ? AND UserID = ? AND Status != "Cancelled"',
      [bookingId, userId]
    );
    if (bookings.length === 0) {
      return res.status(403).json({ error: 'Booking not found or not authorized' });
    }

    // Check if new slot is available (exclude current booking)
    const [existing] = await pool.query(
      'SELECT BookingID FROM Bookings WHERE RoomID = ? AND SlotID = ? AND BookingDate = ? AND Status != "Cancelled" AND BookingID != ?',
      [parsedRoomId, parsedSlotId, date, bookingId]
    );
    if (existing.length > 0) {
      return res.status(409).json({ error: 'This slot is already booked' });
    }

    // Update booking
    const [result] = await pool.query(
      'UPDATE Bookings SET RoomID = ?, SlotID = ?, BookingDate = ?, Reason = ?, Department = ?, Status = ? WHERE BookingID = ? AND UserID = ?',
      [parsedRoomId, parsedSlotId, date, reason, 'development', 'Confirmed', bookingId, userId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Booking not found or not authorized' });
    }

    // Create notification
    const message = `${user[0].FullName} updated a booking for ${room[0].Name} at ${slot[0].Display} on ${date}.`;
    console.log('Attempting to create notification:', { userId, message });
    await createNotification(userId, null, 'BOOKING_UPDATED', message);

    res.status(200).json({ message: 'Booking updated successfully' });
  } catch (err) {
    console.error('Update booking error:', err);
    if (err.code === 'ER_NO_REFERENCED_ROW_2') {
      return res.status(400).json({ error: 'Invalid roomId or slotId: Referenced room or slot does not exist' });
    }
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'This slot is already booked' });
    }
    res.status(500).json({ error: 'Server error' });
  }
});


app.get('/available-slots/today', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT 
        r.RoomID AS roomId,
        r.Name AS roomName,
        t.SlotID AS slotId,
        t.Display AS display
      FROM Rooms r
      CROSS JOIN TimeSlots t
      LEFT JOIN Bookings b 
        ON b.RoomID = r.RoomID 
        AND b.SlotID = t.SlotID 
        AND b.BookingDate = CURDATE()
      WHERE r.IsActive = TRUE
        AND (b.BookingID IS NULL OR b.Status = 'Cancelled')
      ORDER BY r.RoomID, t.StartTime
    `);

    // Group slots by room
    const result = rows.reduce((acc, row) => {
      let room = acc.find(r => r.roomId === row.roomId);
      if (!room) {
        room = {
          roomId: row.roomId,
          roomName: row.roomName,
          slots: []
        };
        acc.push(room);
      }
      room.slots.push({
        slotId: row.slotId,
        display: row.display
      });
      return acc;
    }, []);

    res.json(result);
  } catch (err) {
    console.error('Today available slots error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/available-slots/tomorrow', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT 
        r.RoomID AS roomId,
        r.Name AS roomName,
        t.SlotID AS slotId,
        t.Display AS display
      FROM Rooms r
      CROSS JOIN TimeSlots t
      LEFT JOIN Bookings b 
        ON b.RoomID = r.RoomID 
        AND b.SlotID = t.SlotID 
        AND b.BookingDate = CURDATE() + INTERVAL 1 DAY
      WHERE r.IsActive = TRUE
        AND (b.BookingID IS NULL OR b.Status = 'Cancelled')
      ORDER BY r.RoomID, t.StartTime
    `);

    // Group slots by room
    const result = rows.reduce((acc, row) => {
      let room = acc.find(r => r.roomId === row.roomId);
      if (!room) {
        room = {
          roomId: row.roomId,
          roomName: row.roomName,
          slots: []
        };
        acc.push(room);
      }
      room.slots.push({
        slotId: row.slotId,
        display: row.display
      });
      return acc;
    }, []);

    res.json(result);
  } catch (err) {
    console.error('Tomorrow available slots error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/available-slots', authenticateToken, async (req, res) => {
  try {
    const { date } = req.query;
    if (!date) {
      return res.status(400).json({ error: 'Date is required' });
    }
    const [rows] = await pool.query(`
      SELECT 
        r.RoomID AS roomId,
        r.Name AS roomName,
        t.SlotID AS slotId,
        t.Display AS display
      FROM Rooms r
      CROSS JOIN TimeSlots t
      LEFT JOIN Bookings b 
        ON b.RoomID = r.RoomID 
        AND b.SlotID = t.SlotID 
        AND b.BookingDate = ?
      WHERE r.IsActive = TRUE
        AND (b.BookingID IS NULL OR b.Status = 'Cancelled')
      ORDER BY r.RoomID, t.StartTime
    `, [date]);

    // Group slots by room
    const result = rows.reduce((acc, row) => {
      let room = acc.find(r => r.roomId === row.roomId);
      if (!room) {
        room = {
          roomId: row.roomId,
          roomName: row.roomName,
          slots: []
        };
        acc.push(room);
      }
      room.slots.push({
        slotId: row.slotId,
        display: row.display
      });
      return acc;
    }, []);

    res.json(result);
  } catch (err) {
    console.error('Available slots error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all notifications (for all users)
app.get('/notifications', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT 
        n.NotificationID AS id,
        n.UserID AS userId,
        COALESCE(u.FullName, 'System') AS userName,
        n.Type AS type,
        n.Message AS message,
        n.CreatedAt AS createdAt,
        n.IsRead AS isRead
      FROM Notifications n
      LEFT JOIN Users u ON n.UserID = u.UserID
      WHERE n.RecipientID IS NULL
      ORDER BY n.CreatedAt DESC
    `);
    res.json(rows);
  } catch (err) {
    console.error('Notifications error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user-specific notifications (e.g., reminders)
app.get('/notifications/me', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.UserID;
    const [rows] = await pool.query(`
      SELECT 
        n.NotificationID AS id,
        n.UserID AS userId,
        COALESCE(u.FullName, 'System') AS userName,
        n.Type AS type,
        n.Message AS message,
        n.CreatedAt AS createdAt,
        n.IsRead AS isRead
      FROM Notifications n
      LEFT JOIN Users u ON n.UserID = u.UserID
      WHERE n.RecipientID = ?
      ORDER BY n.CreatedAt DESC
    `, [userId]);
    res.json(rows);
  } catch (err) {
    console.error('User notifications error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Mark notification as read
app.put('/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.UserID;
    const notificationId = req.params.id;
    const [result] = await pool.query(
      'UPDATE Notifications SET IsRead = TRUE WHERE NotificationID = ? AND (RecipientID = ? OR RecipientID IS NULL)',
      [notificationId, userId]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Notification not found or not authorized' });
    }
    res.json({ message: 'Notification marked as read' });
  } catch (err) {
    console.error('Mark notification read error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});



app.put("/api/password", authenticateToken, async (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;
  const userId = req.user.UserID;
  try {
    // Validate input
    if (!currentPassword || !newPassword || !confirmPassword) {
      return res
        .status(400)
        .json({ error: "All password fields are required" });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: "New passwords do not match" });
    }

    // Password validation regex
    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]).{8,}$/;
    if (!passwordRegex.test(newPassword) || /\s/.test(newPassword)) {
      return res.status(400).json({
        error:
          "Password must be at least 8 characters, include one uppercase, one lowercase, one number, one special character, and no spaces",
      });
    }

    // Fetch user
    const [users] = await pool.query(
      "SELECT PasswordHash, Email, FullName FROM Users WHERE UserID = ?",
      [userId]
    );
    if (users.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    const user = users[0];

    // Verify current password
    const isMatch = await bcrypt.compare(currentPassword, user.PasswordHash);
    if (!isMatch) {
      return res.status(401).json({ error: "Current password is incorrect" });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password
    await pool.query(
      "UPDATE Users SET PasswordHash = ? WHERE UserID = ?",
      [hashedPassword, userId]
    );

    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("Error updating password:", err);
    res.status(500).json({ error: "Server error" });
  }
});



app.post('/admin/signup', async (req, res) => {
  try {
    const { fullname, email, password, phone, department, profile_photo } = req.body;

    if (!fullname || !email || !password || !department || !phone) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if email already exists in admin table
    const [existing] = await pool.query('SELECT email FROM admin WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    await pool.query(
      'INSERT INTO admin (fullname, email, password, phone, department, profile_photo, role) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [fullname, email, passwordHash, phone, department, profile_photo || null, 'admin']
    );

    res.status(201).json({ message: 'Admin registered successfully' });
  } catch (err) {
    console.error('Admin Sign-up error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});


// Admin Login API
// app.post('/admin/login', async (req, res) => {
//   try {
//     console.log('Received body:', req.body);
//     const { email, password } = req.body;

//     if (!email || !password) {
//       return res.status(400).json({ error: 'Email and Password are required' });
//     }

//     // Query active admin by email
//     const [admins] = await pool.query(
//       'SELECT * FROM admin WHERE email = ? AND isactive = 1',
//       [email]
//     );

//     if (admins.length === 0) {
//       return res.status(401).json({ error: 'Invalid credentials' });
//     }

//     const admin = admins[0];

//     // Compare password hashes
//     const isMatch = await bcrypt.compare(password, admin.password);
//     if (!isMatch) {
//       return res.status(401).json({ error: 'Invalid credentials' });
//     }

//     // Create JWT token with admin info
//     const token = jwt.sign(
//       { adminid: admin.adminid, email: admin.email, role: admin.role },
//       process.env.JWT_SECRET || 'your-secret-key',
//       { expiresIn: '1h' }
//     );

//     res.json({
//       message: 'Login successful',
//       token,
//       admin: {
//         adminid: admin.adminid,
//         fullname: admin.fullname,
//         email: admin.email,
//         role: admin.role,
//         phone: admin.phone,
//         department: admin.department,
//         profile_photo: admin.profile_photo || null,
//       },
//     });
//   } catch (err) {
//     console.error('Admin login error:', err);
//     res.status(500).json({ error: 'Server error' });
//   }
// });

app.post('/admin/login', async (req, res) => {
  try {
    console.log('Received body:', req.body);
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and Password are required' });
    }

    // First: Find admin by email regardless of active status
    const [adminRows] = await pool.query(
      'SELECT * FROM admin WHERE email = ?',
      [email]
    );

    if (adminRows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const admin = adminRows[0];

    // Check if admin is active
    if (admin.isactive !== 1) {
      return res.status(403).json({ error: 'Your admin account is inactive. Please contact support.' });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Create token
    const token = jwt.sign(
      { adminid: admin.adminid, email: admin.email, role: admin.role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    // Success response
    res.json({
      message: 'Login successful',
      token,
      admin: {
        adminid: admin.adminid,
        fullname: admin.fullname,
        email: admin.email,
        role: admin.role,
        phone: admin.phone,
        department: admin.department,
        profile_photo: admin.profile_photo || null,
      },
    });
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});


// Assuming you already have express, jwt, bcrypt, mysql2/promise pool and authenticateAdmin middleware set up

app.get('/admin/profile', authenticateAdmin, async (req, res) => {
  try {
    // `authenticateAdmin` middleware sets decoded token data in req.admin
    const adminId = req.admin.adminid;

    // Query admin details by adminid
    const [rows] = await pool.query(
      'SELECT adminid, fullname, email, role, phone, department, profile_photo, isactive, created_at FROM admin WHERE adminid = ?',
      [adminId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Admin not found' });
    }

    const admin = rows[0];

    // Return full admin profile data
    res.json({ admin });
  } catch (error) {
    console.error('Error fetching admin profile:', error);
    res.status(500).json({ error: 'Server error' });
  }
});


app.put('/admin/password', authenticateAdmin, async (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;
  const adminId = req.admin.adminid;

  try {
    // Validate request body
    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({ error: 'All password fields are required' });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: 'New passwords do not match' });
    }

    // Password complexity regex:
    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]).{8,}$/;

    if (!passwordRegex.test(newPassword) || /\s/.test(newPassword)) {
      return res.status(400).json({
        error:
          'Password must be at least 8 characters, include one uppercase, one lowercase, one number, one special character, and no spaces',
      });
    }

    // Fetch admin's current password hash
    const [admins] = await pool.query(
      'SELECT password, email, fullname FROM admin WHERE adminid = ?',
      [adminId]
    );

    if (admins.length === 0) {
      return res.status(404).json({ error: 'Admin not found' });
    }

    const admin = admins[0];

    // Verify current password
    const isMatch = await bcrypt.compare(currentPassword, admin.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password in database
    await pool.query(
      'UPDATE admin SET password = ? WHERE adminid = ?',
      [hashedPassword, adminId]
    );

    return res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error('Error updating admin password:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.put('/admin/profile', authenticateAdmin, async (req, res) => {
  try {
    const adminId = req.admin.adminid;
    const { fullname, email, phone, department } = req.body;

    // Basic validation
    if (!fullname || !email || !phone || !department) {
      return res.status(400).json({ error: 'All fields (fullname, email, phone, department) are required.' });
    }

    // Check if email is already used by another admin
    const [existingEmails] = await pool.query(
      'SELECT adminid FROM admin WHERE email = ? AND adminid != ?',
      [email, adminId]
    );

    if (existingEmails.length > 0) {
      return res.status(400).json({ error: 'Email is already in use by another account.' });
    }

    // Update the admin profile
    await pool.query(
      `UPDATE admin 
       SET fullname = ?, email = ?, phone = ?, department = ? 
       WHERE adminid = ?`,
      [fullname, email, phone, department, adminId]
    );

    // Fetch the updated data to send back
    const [updated] = await pool.query(
      `SELECT adminid, fullname, email, role, phone, department, profile_photo, isactive, created_at
      FROM admin WHERE adminid = ?`,
      [adminId]
    );

    if (updated.length === 0) {
      return res.status(404).json({ error: 'Admin not found after update' });
    }

    return res.json({ message: 'Profile updated successfully', admin: updated[0] });
  } catch (error) {
    console.error('Error updating admin profile:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});


app.post('/admin/rooms', authenticateAdmin, async (req, res) => {
  try {
    const { name, description, maxCapacity, features, imageUrl } = req.body;
    if (!name || !maxCapacity) {
      return res.status(400).json({ error: 'Name and maxCapacity are required' });
    }
    const [result] = await pool.query(
      `INSERT INTO Rooms (Name, Capacity, Description, Products, ImageUrl, IsActive) VALUES (?, ?, ?, ?, ?, 1)`,
      [name, maxCapacity, description || null, features || null, imageUrl || null]
    );

    res.status(201).json({ message: 'Room added', roomId: result.insertId });
  } catch (error) {
    console.error('Error adding room:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/admin/rooms', authenticateAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM Rooms');
    res.json({ rooms: rows });
  } catch (error) {
    console.error('Error fetching rooms:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/admin/rooms/:id', authenticateAdmin, async (req, res) => {
  try {
    const roomId = req.params.id;
    const { name, description, maxCapacity, features, imageUrl, isActive } = req.body;
    const [result] = await pool.query(
      `UPDATE Rooms SET Name = ?, Capacity = ?, Description = ?, Products = ?, ImageUrl = ?, IsActive = ? WHERE RoomID = ?`,
      [name, maxCapacity, description, features, imageUrl, isActive, roomId]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Room not found' });
    }
    res.json({ message: 'Room updated' });
  } catch (error) {
    console.error('Error updating room:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/admin/rooms/:id', authenticateAdmin, async (req, res) => {
  try {
    const roomId = req.params.id;
    const [result] = await pool.query(`DELETE FROM Rooms WHERE RoomID = ?`, [roomId]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Room not found' });
    }
    res.json({ message: 'Room deleted' });
  } catch (error) {
    console.error('Error deleting room:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/admin/rooms/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const roomId = req.params.id;
    const { isActive } = req.body; // boolean
    if (typeof isActive !== 'boolean') {
      return res.status(400).json({ error: 'isActive must be boolean' });
    }
    const [result] = await pool.query(`UPDATE Rooms SET IsActive = ? WHERE RoomID = ?`, [
      isActive ? 1 : 0,
      roomId,
    ]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Room not found' });
    }
    res.json({ message: `Room ${isActive ? 'activated' : 'deactivated'}` });
  } catch (error) {
    console.error('Error toggling room status:', error);
    res.status(500).json({ error: 'Server error' });
  }
});


app.get('/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const [users] = await pool.query(`
      SELECT UserID, FullName, Email, Role, Department, Phone, IsActive, CreatedAt
      FROM Users
      ORDER BY CreatedAt DESC
    `);
    res.json({ users });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Server error' });
  }
});


app.delete('/admin/users/:id', authenticateAdmin, async (req, res) => {
  const userId = req.params.id;

  try {
    const [result] = await pool.query('DELETE FROM Users WHERE UserID = ?', [userId]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/admin/users/:id/status', authenticateAdmin, async (req, res) => {
  const userId = req.params.id;
  const { isActive } = req.body; // Boolean expected

  if (typeof isActive !== 'boolean') {
    return res.status(400).json({ error: 'isActive must be boolean' });
  }

  try {
    const [result] = await pool.query('UPDATE Users SET IsActive = ? WHERE UserID = ?', [
      isActive ? 1 : 0,
      userId,
    ]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ message: `User ${isActive ? 'activated' : 'deactivated'}` });
  } catch (error) {
    console.error('Error toggling user status:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/admin/bookings', authenticateAdmin, async (req, res) => {
  try {
    const query = `
      SELECT 
        b.BookingID, b.BookingDate, b.SlotID, b.Reason, b.Department,
        b.Status,
        u.UserID, u.FullName AS UserName,
        r.RoomID, r.Name AS RoomName,
        s.StartTime, s.EndTime
      FROM Bookings b
      JOIN Users u ON b.UserID = u.UserID
      JOIN Rooms r ON b.RoomID = r.RoomID
      JOIN Slots s ON b.SlotID = s.SlotID
      ORDER BY b.BookingDate DESC, s.StartTime DESC
      LIMIT 100
    `;

    const [rows] = await pool.query(query);

    res.json({ bookings: rows });
  } catch (error) {
    console.error('Error fetching bookings:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/bookings/all', authenticateAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT 
         b.BookingID AS id, 
         u.FullName AS name,
         COALESCE(r.Name, 'Unknown Room') AS room, 
         b.BookingDate AS date, 
         t.Display AS time, 
         b.Reason AS reason, 
         b.Status AS status, 
         b.Department AS department, 
         r.Products AS products
       FROM Bookings b
       JOIN Rooms r ON b.RoomID = r.RoomID
       JOIN TimeSlots t ON b.SlotID = t.SlotID
       JOIN Users u ON b.UserID = u.UserID
       ORDER BY b.BookingDate DESC, t.StartTime ASC
      `
    );

    const bookings = rows.map(row => ({
      ...row,
      products: row.products ? row.products.split(',') : [],
    }));

    res.json(bookings);
  } catch (err) {
    console.error('Bookings error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});


app.put('/admin/bookings/:bookingId/cancel', authenticateAdmin, async (req, res) => {
  const bookingId = req.params.bookingId;

  try {
    // Check if booking exists and is not already cancelled or completed
    const [bookingRows] = await pool.query(
      'SELECT Status FROM Bookings WHERE BookingID = ?',
      [bookingId]
    );

    if (bookingRows.length === 0) {
      return res.status(404).json({ error: 'Booking not found' });
    }

    const booking = bookingRows[0];
    if (booking.Status === 'Cancelled' || booking.Status === 'Completed') {
      return res.status(400).json({ error: `Booking already ${booking.Status.toLowerCase()}` });
    }

    // Update status to Cancelled
    await pool.query(
      'UPDATE Bookings SET Status = ? WHERE BookingID = ?',
      ['Cancelled', bookingId]
    );

    res.json({ message: 'Booking cancelled successfully' });
  } catch (error) {
    console.error('Error cancelling booking:', error);
    res.status(500).json({ error: 'Server error' });
  }
});


app.get('/bookings/counts', authenticateAdmin, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();

    // Get current date for frontend display (YYYY-MM-DD)
    const today = new Date().toISOString().split('T')[0];

    // Query for total bookings count
    const [totalBookingsResult] = await connection.query(
      `SELECT COUNT(*) AS totalBookings FROM Bookings`
    );

    // Query for today's bookings count
    const [todayBookingsResult] = await connection.query(
      `SELECT COUNT(*) AS todayBookings FROM Bookings WHERE BookingDate = CURRENT_DATE`
    );

    // Query for total active users count
    const [totalUsersResult] = await connection.query(
      `SELECT COUNT(*) AS totalUsers FROM Users WHERE IsActive = 1`
    );

    // Query for total active rooms count
    const [totalRoomsResult] = await connection.query(
      `SELECT COUNT(*) AS totalRooms FROM Rooms WHERE IsActive = 1`
    );

    res.status(200).json({
      totalBookings: totalBookingsResult[0].totalBookings,
      todayBookings: todayBookingsResult[0].todayBookings,
      todayDate: today,
      totalUsers: totalUsersResult[0].totalUsers,
      totalRooms: totalRoomsResult[0].totalRooms
    });
  } catch (error) {
    console.error('Error fetching counts:', error);
    if (error.code === 'ER_NO_SUCH_TABLE') {
      res.status(500).json({ error: `Database table not found: ${error.sqlMessage}` });
    } else if (error.code === 'ER_ACCESS_DENIED_ERROR') {
      res.status(500).json({ error: 'Database access denied' });
    } else if (error.code === 'ER_BAD_FIELD_ERROR') {
      res.status(500).json({ error: `Invalid column name: ${error.sqlMessage}` });
    } else {
      res.status(500).json({ error: 'Failed to fetch counts' });
    }
  } finally {
    if (connection) connection.release();
  }
});

// GET /admin/bookings/weekly - Fetch day-wise booking counts for the past 7 days
app.get('/bookings/weekly', authenticateAdmin, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();

    // Get current date in IST
    const today = new Date().toLocaleString('en-US', { timeZone: 'Asia/Kolkata' });
    const todayDate = new Date(today);

    // Get Monday (start of week) and Sunday (end of week)
    const day = todayDate.getDay(); // 0 (Sun) to 6 (Sat)
    const diffToMonday = (day + 6) % 7; // Days to subtract to get to Monday
    const startOfWeek = new Date(todayDate);
    startOfWeek.setDate(todayDate.getDate() - diffToMonday);
    startOfWeek.setHours(0, 0, 0, 0);

    const endOfWeek = new Date(startOfWeek);
    endOfWeek.setDate(startOfWeek.getDate() + 6);
    endOfWeek.setHours(23, 59, 59, 999);

    const startDateStr = startOfWeek.toISOString().split('T')[0];
    const endDateStr = endOfWeek.toISOString().split('T')[0];

    // MySQL query using IST time zone conversion
    const [results] = await connection.query(
      `SELECT 
         DATE(CONVERT_TZ(BookingDate, @@session.time_zone, '+05:30')) AS date, 
         COUNT(*) AS count 
       FROM Bookings 
       WHERE DATE(CONVERT_TZ(BookingDate, @@session.time_zone, '+05:30')) BETWEEN ? AND ?
       GROUP BY date
       ORDER BY date ASC`,
      [startDateStr, endDateStr]
    );

    // Create labels from Monday to Sunday
    const labels = [];
    const data = [];

    for (let i = 0; i < 7; i++) {
      const date = new Date(startOfWeek);
      date.setDate(startOfWeek.getDate() + i);
      const label = date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }); // "Jul 22"
      const isoDate = date.toISOString().split('T')[0]; // "2025-07-22"

      labels.push(label);
      const result = results.find(r => r.date.toISOString().split('T')[0] === isoDate);
      data.push(result ? result.count : 0);
    }

    res.status(200).json({ labels, data });
  } catch (error) {
    console.error('Error fetching weekly bookings:', error);
    res.status(500).json({ error: 'Failed to fetch weekly bookings' });
  } finally {
    if (connection) connection.release();
  }
});


// GET /admin/bookings/room-usage - Fetch booking counts per room
app.get('/bookings/room-usage', authenticateAdmin, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();

    // Query for booking counts for Samvad (RoomID: 1) and Arohan (RoomID: 2)
    const [results] = await connection.query(
      `SELECT 
         r.Name AS roomName, 
         COUNT(b.BookingID) AS count 
       FROM Rooms r 
       LEFT JOIN Bookings b ON r.RoomID = b.RoomID 
       WHERE r.RoomID IN (1, 2) AND r.IsActive = 1 
       GROUP BY r.RoomID, r.Name`
    );

    // Format response
    const labels = results.map(r => r.roomName);
    const data = results.map(r => Math.min(r.count, 100)); // Cap at 100 for y-axis

    res.status(200).json({ labels, data });
  } catch (error) {
    console.error('Error fetching room usage:', error);
    if (error.code === 'ER_NO_SUCH_TABLE') {
      res.status(500).json({ error: `Database table not found: ${error.sqlMessage}` });
    } else if (error.code === 'ER_ACCESS_DENIED_ERROR') {
      res.status(500).json({ error: 'Database access denied' });
    } else if (error.code === 'ER_BAD_FIELD_ERROR') {
      res.status(500).json({ error: `Invalid column name: ${error.sqlMessage}` });
    } else {
      res.status(500).json({ error: 'Failed to fetch room usage' });
    }
  } finally {
    if (connection) connection.release();
  }
});



app.get('/mybookings/counts', authenticateAdmin, async (req, res) => {
  const { period = 'all' } = req.query;
  let connection;

  try {
    connection = await pool.getConnection();

    // Get date filter based on period
    const now = new Date();
    let startDate = null;
    if (period === 'week') {
      const day = now.getDay();
      const diffToMonday = (day + 6) % 7;
      now.setDate(now.getDate() - diffToMonday);
      startDate = now.toISOString().split('T')[0];
    } else if (period === 'month') {
      now.setDate(now.getDate() - 30);
      startDate = now.toISOString().split('T')[0];
    }

    const dateFilter = startDate ? `WHERE BookingDate >= '${startDate}'` : '';

    // Bookings Count
    const [[{ totalBookings }]] = await connection.query(
      `SELECT COUNT(*) AS totalBookings FROM Bookings ${dateFilter}`
    );
    const [[{ cancelledBookings }]] = await connection.query(
      `SELECT COUNT(*) AS cancelledBookings FROM Bookings 
       WHERE Status = 'Cancelled' ${startDate ? `AND BookingDate >= '${startDate}'` : ''}`
    );

    // Users Count (no filter needed)
    const [[{ totalUsers }]] = await connection.query(`SELECT COUNT(*) AS totalUsers FROM Users`);
    const [[{ totalRooms }]] = await connection.query(`SELECT COUNT(*) AS totalRooms FROM Rooms`);

    res.json({ totalBookings, cancelledBookings, totalUsers, totalRooms });
  } catch (err) {
    console.error('Counts API Error:', err);
    res.status(500).json({ error: 'Failed to fetch counts' });
  } finally {
    if (connection) connection.release();
  }
});

app.get('/mybookings/room-usage', authenticateAdmin, async (req, res) => {
  const { period = 'all' } = req.query;
  let connection;

  try {
    connection = await pool.getConnection();

    let dateCondition = '';
    if (period !== 'all') {
      const now = new Date();
      now.setDate(now.getDate() - (period === 'week' ? 7 : 30));
      const dateStr = now.toISOString().split('T')[0];
      dateCondition = `AND BookingDate >= '${dateStr}'`;
    }

    const [results] = await connection.query(`
      SELECT r.Name AS room, COUNT(b.BookingID) AS bookings
      FROM Rooms r
      LEFT JOIN Bookings b ON r.RoomID = b.RoomID AND b.Status = 'Approved' ${dateCondition}
      GROUP BY r.RoomID
      ORDER BY bookings DESC
    `);

    res.json({ labels: results.map(r => r.room), data: results.map(r => r.bookings) });
  } catch (err) {
    console.error('Room Usage Error:', err);
    res.status(500).json({ error: 'Failed to fetch room usage' });
  } finally {
    if (connection) connection.release();
  }
});

app.get('/bookings/peak-hours', authenticateAdmin, async (req, res) => {
  const { period = 'all' } = req.query;
  let connection;

  try {
    connection = await pool.getConnection();

    let dateCondition = '';
    if (period !== 'all') {
      const now = new Date();
      now.setDate(now.getDate() - (period === 'week' ? 7 : 30));
      const dateStr = now.toISOString().split('T')[0];
      dateCondition = `AND BookingDate >= '${dateStr}'`;
    }

    const [rows] = await connection.query(`
      SELECT HOUR(CreatedAt) AS hour, COUNT(*) AS count
      FROM Bookings
      WHERE Status = 'Approved' ${dateCondition}
      GROUP BY hour
      ORDER BY hour
    `);

    const hours = Array(24).fill(0);
    rows.forEach(r => {
      hours[r.hour] = r.count;
    });

    res.json({
      labels: Array.from({ length: 9 }, (_, i) => `${9 + i}AM`),
      data: hours.slice(9, 18)
    });
  } catch (err) {
    console.error('Peak Hours Error:', err);
    res.status(500).json({ error: 'Failed to fetch peak hours' });
  } finally {
    if (connection) connection.release();
  }
});


app.get('/bookings/top-users', authenticateAdmin, async (req, res) => {
  const { period = 'all' } = req.query;
  let connection;

  try {
    connection = await pool.getConnection();

    let dateCondition = '';
    if (period !== 'all') {
      const now = new Date();
      now.setDate(now.getDate() - (period === 'week' ? 7 : 30));
      const dateStr = now.toISOString().split('T')[0];
      dateCondition = `AND BookingDate >= '${dateStr}'`;
    }

    const [rows] = await connection.query(`
      SELECT u.FullName AS name, COUNT(b.BookingID) AS bookings
      FROM Users u
      JOIN Bookings b ON u.UserID = b.UserID
      WHERE b.Status = 'Approved' ${dateCondition}
      GROUP BY u.UserID
      ORDER BY bookings DESC
      LIMIT 5
    `);

    res.json({
      labels: rows.map(r => r.name.split(' ')[0]),
      data: rows.map(r => r.bookings)
    });
  } catch (err) {
    console.error('Top Users Error:', err);
    res.status(500).json({ error: 'Failed to fetch top users' });
  } finally {
    if (connection) connection.release();
  }
});


app.post('/admin/bookings', authenticateAdmin, async (req, res) => {
  try {
    const { roomId, slotId, date, reason } = req.body;

    // Check if req.admin exists
    if (!req.admin) {
      return res.status(401).json({ error: 'Authentication failed: No admin data' });
    }

    const adminId = req.admin.adminid; // Changed from req.adminid to req.admin.adminid
    if (!adminId) {
      return res.status(400).json({ error: 'Invalid user data: adminid missing' });
    }

    if (!roomId || !slotId || !date || !reason) {
      return res.status(400).json({ error: 'roomId, slotId, date, and reason are required' });
    }

    // Validate date format (YYYY-MM-DD)
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ error: 'Invalid date format. Use YYYY-MM-DD' });
    }

    const [existing] = await pool.query(
      'SELECT BookingID FROM Bookings WHERE RoomID = ? AND SlotID = ? AND BookingDate = ? AND Status != "Cancelled"',
      [roomId, slotId, date]
    );
    if (existing.length > 0) {
      return res.status(409).json({ error: 'This slot is already booked' });
    }
    


    
    const [adminexisting] = await pool.query(
      'SELECT BookingID FROM Admin_Booking WHERE RoomID = ? AND SlotID = ? AND BookingDate = ? AND Status != "Cancelled"',
      [roomId, slotId, date]
    );
    if (adminexisting.length > 0) {
      return res.status(409).json({ error: 'This slot is already booked' });
    }
    const [room] = await pool.query('SELECT Name FROM Rooms WHERE RoomID = ?', [roomId]);
    const [slot] = await pool.query('SELECT Display FROM TimeSlots WHERE SlotID = ?', [slotId]);
    if (!room.length || !slot.length) {
      return res.status(404).json({ error: 'Room or slot not found' });
    }

    const [admin] = await pool.query('SELECT fullname FROM admin WHERE adminid = ?', [adminId]);
    if (!admin.length) {
      return res.status(404).json({ error: 'Admin not found' });
    }

    await pool.query(
      'INSERT INTO Admin_Booking (admin_id, RoomID, SlotID, BookingDate, Reason, Status, Department) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [adminId, roomId, slotId, date, reason, 'Confirmed', req.admin.department || 'Admin']
    );

    
    res.status(201).json({ message: 'Booking created successfully' });
  } catch (err) {
    console.error('Admin booking error:', err);
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'This slot is already booked' });
    }
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});



app.get('/admin/mybooking', authenticateAdmin, async (req, res) => {
  try {
    if (!req.admin) {
      return res.status(401).json({ error: 'Authentication failed: No admin data' });
    }

    const adminId = req.admin.adminid;
    if (!adminId) {
      return res.status(400).json({ error: 'Invalid user data: adminid missing' });
    }

    // Get query parameters for filtering
    const { roomId, date, status, admin_id } = req.query;

    // Build the SQL query dynamically
    let query = `
     SELECT 
  ab.BookingID,
  ab.admin_id,
  ab.RoomID,
  r.Name AS RoomName,
  ab.SlotID,
  ts.Display AS SlotDisplay,
  DATE_FORMAT(ab.BookingDate, '%Y-%m-%d') AS BookingDate,
  ab.Reason,
  ab.Department,
  ab.Status,
  ab.CreatedAt,
  a.fullname AS AdminName
FROM Admin_Booking ab

      JOIN Rooms r ON ab.RoomID = r.RoomID
      JOIN TimeSlots ts ON ab.SlotID = ts.SlotID
      JOIN admin a ON ab.admin_id = a.adminid
    `;
    const queryParams = [];
    const conditions = [];

    // Add filters
    if (roomId) {
      conditions.push('ab.RoomID = ?');
      queryParams.push(roomId);
    }
    if (date) {
      // Validate YYYY-MM-DD format
      if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
        return res.status(400).json({ error: 'Invalid date format. Use YYYY-MM-DD' });
      }
      conditions.push('ab.BookingDate = ?');
      queryParams.push(date);
    }
    if (status) {
      if (!['Pending', 'Confirmed', 'Cancelled', 'Completed'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status. Use Pending, Confirmed, Cancelled, or Completed' });
      }
      conditions.push('ab.Status = ?');
      queryParams.push(status);
    }
    if (admin_id) {
      conditions.push('ab.admin_id = ?');
      queryParams.push(admin_id);
    } else {
      conditions.push('ab.admin_id = ?');
      queryParams.push(adminId);
    }

    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }

    query += ' ORDER BY ab.BookingDate DESC, ab.CreatedAt DESC';

    // Execute the query
    const [bookings] = await pool.query(query, queryParams);

    // No need to mess with Date objects, already a DATE in DB
    // Send iso date string as-is
    res.status(200).json({
      message: 'Bookings retrieved successfully',
      bookings: bookings.map(booking => ({
        bookingId: booking.BookingID,
        adminId: booking.admin_id,
        adminName: booking.AdminName,
        roomId: booking.RoomID,
        roomName: booking.RoomName,
        slotId: booking.SlotID,
        slotDisplay: booking.SlotDisplay,
        bookingDate: booking.BookingDate, // YYYY-MM-DD, already correct
        reason: booking.Reason,
        department: booking.Department,
        status: booking.Status,
        createdAt: booking.CreatedAt
      }))
    });
  } catch (err) {
    console.error('Admin bookings retrieval error:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});



app.get('/bookings/admincounts', authenticateAdmin, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();

    // Get current date for frontend display (YYYY-MM-DD)
    const today = new Date().toISOString().split('T')[0];

    // Query for total bookings count
    const [totalBookingsResult] = await connection.query(
      `SELECT COUNT(*) AS totalBookings FROM Admin_Booking`
    );

    // Query for today's bookings count
    const [todayBookingsResult] = await connection.query(
      `SELECT COUNT(*) AS todayBookings FROM Admin_Booking WHERE BookingDate = CURRENT_DATE`
    );

    // Query for total active users count
    const [totalUsersResult] = await connection.query(
      `SELECT COUNT(*) AS totalUsers FROM admin WHERE IsActive = 1`
    );

    // Query for total active rooms count
    const [totalRoomsResult] = await connection.query(
      `SELECT COUNT(*) AS totalRooms FROM Rooms WHERE IsActive = 1`
    );

    res.status(200).json({
      totaladminBookings: totalBookingsResult[0].totalBookings,
      todaysadminBookings: todayBookingsResult[0].todayBookings,
      todayDate: today,
      totalAdmins: totalUsersResult[0].totalUsers,
      totalRooms: totalRoomsResult[0].totalRooms
    });
  } catch (error) {
    console.error('Error fetching counts:', error);
    if (error.code === 'ER_NO_SUCH_TABLE') {
      res.status(500).json({ error: `Database table not found: ${error.sqlMessage}` });
    } else if (error.code === 'ER_ACCESS_DENIED_ERROR') {
      res.status(500).json({ error: 'Database access denied' });
    } else if (error.code === 'ER_BAD_FIELD_ERROR') {
      res.status(500).json({ error: `Invalid column name: ${error.sqlMessage}` });
    } else {
      res.status(500).json({ error: 'Failed to fetch counts' });
    }
  } finally {
    if (connection) connection.release();
  }
});


app.get('/admin/all', async (req, res) => {
  try {
    const query = `
      SELECT 
        adminid, fullname, email, phone, department,
        isactive, created_at
      FROM admin
      WHERE role = 'admin'
      ORDER BY created_at DESC
    `;
    const [admins] = await pool.query(query);
    res.status(200).json({ admins });
  } catch (err) {
    console.error('Error fetching all admins:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/admin/status/:adminid', async (req, res) => {
  try {
    const { adminid } = req.params;

    if (!adminid || isNaN(Number(adminid))) {
      return res.status(400).json({ error: 'Invalid admin ID' });
    }

    const { isactive } = req.body;

    if (typeof isactive !== 'number' || ![0, 1].includes(isactive)) {
      return res.status(400).json({ error: 'Invalid isactive value. Must be 0 or 1.' });
    }

    const query = 'UPDATE admin SET isactive = ? WHERE adminid = ?';
    const [result] = await pool.query(query, [isactive, adminid]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Admin not found' });
    }

    res.status(200).json({ success: true, adminid, isactive });
  } catch (err) {
    console.error('Update isactive error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});


cron.schedule('* * * * *', async () => {
  try {
    const now = new Date();
    const reminderTime = new Date(now.getTime() + 15 * 60 * 1000);
    const [bookings] = await pool.query(
      `SELECT b.*, r.Name AS RoomName, t.Display AS SlotDisplay
       FROM Bookings b
       JOIN Rooms r ON b.RoomID = r.RoomID
       JOIN TimeSlots t ON b.SlotID = t.SlotID
       WHERE b.BookingDate = CURDATE()
       AND b.Status = 'Confirmed'
       AND TIME(t.StartTime) BETWEEN TIME(?) AND TIME(?)`,
      [now, reminderTime]
    );

    for (const booking of bookings) {
      const message = `Reminder: Your meeting in ${booking.RoomName} at ${booking.SlotDisplay} is starting in 15 minutes.`;
      await createNotification(null, booking.UserID, 'MEETING_REMINDER', message);
    }
    console.log('Cron job executed: Checked for meeting reminders');
  } catch (err) {
    console.error('Error in cron job:', err);
  }
});



app.listen(port, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${port}`);
});
