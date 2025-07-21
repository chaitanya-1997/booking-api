

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
      { expiresIn: '1h' }
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
    const { roomId, slotId, date, reason, department } = req.body;
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
      [userId, roomId, slotId, date, reason, 'Confirmed', null]
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
       WHERE b.UserID = ? AND b.Status != 'Cancelled'`,
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
    const { roomId, slotId, date, reason, department } = req.body;

    if (!roomId || !slotId || !date || !reason || !department) {
      return res.status(400).json({ error: 'roomId, slotId, date, reason, and department are required' });
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
      [parsedRoomId, parsedSlotId, date, reason, department, 'Confirmed', bookingId, userId]
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

// Cron job for meeting reminders
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