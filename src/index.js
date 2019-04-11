import {
  ApolloServer,
  gql,
  AuthenticationError,
  ForbiddenError,
} from 'apollo-server';
import _ from 'lodash';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

const APP_SECRET =
  "App Secret Key; For example only! Don't define one in code!!!";

// Construct a schema, using GraphQL schema language
const typeDefs = gql`
  type Query {
    users: [User]
    students: [Student]
    faculty: [Faculty]
    currentUser: User
  }

  type Mutation {
    loginUser(email: String!, password: String!): AuthPayload
    logoutUser: Boolean

    # Only Admin can create/update users
    createUser(user: UserInput): User
    updateUser(id: ID!, user: UserInput): User

    # Only Faculty can create/update and manage courses
    createCourse(name: String!, facultyID: ID!): Course
    deleteCourse(courseID: ID!): Course
    addCourseStudent(courseID: ID!, studentID: ID!): Course
    deleteCourseStudent(courseID: ID!, studentID: ID!): Course

    createAssignment(courseID: ID!, name: String!): Assignment
    createAssignmentGrade(
      assignmentID: ID!
      studentID: ID!
      grade: Float!
    ): AssignmentGrade
  }

  # extra credit: monitor when assignments are add
  type Subscription {
    assignmentAdded(studentID: ID!): Assignment
  }

  type AuthPayload {
    token: String
    user: User
  }

  input UserInput {
    # First and last name
    name: String!
    email: String!
    role: Role
    password: String
  }

  enum Role {
    Admin
    Student
    Faculty
  }

  interface User {
    id: ID!
    name: String!
    email: String!
    role: Role!
  }

  type Student implements User {
    id: ID!
    name: String!
    email: String!
    role: Role!
    courses: [Course]
    assignments: [Assignment]
    gpa: Float!
  }

  type Faculty implements User {
    id: ID!
    name: String!
    email: String!
    role: Role!
    courses: [Course]
  }

  type Admin implements User {
    id: ID!
    name: String!
    email: String!
    role: Role!
  }

  type Course {
    id: ID!
    name: String!
    professor: Faculty
    students: [Student]
    assignments: [Assignment]
  }

  type Assignment {
    id: ID!
    name: String!
    course: Course!
    grades: [AssignmentGrade]
  }

  type AssignmentGrade {
    id: ID!
    assignment: Assignment
    student: User
    grade: String!
  }
`;

class UserSessions {
  userSessions = [];
  nextID = 0;

  getSession(sessionID) {
    const i = _.findIndex(this.userSessions, u => u.id === sessionID);
    return i === -1 ? null : this.userSessions[i];
  }

  createSession(userID, secret, expiresIn = 60 * 10) {
    const session = { id: this.nextID, userID: userID };
    this.nextID++;

    const token = jwt.sign({ id: userID, sessionID: session.id }, secret, {
      expiresIn,
    });

    this.userSessions.push(session);
    return token;
  }

  invalidateSession(sessionID) {
    this.userSessions = _.remove(this.userSessions, s => s.id === sessionID);
  }
}

class Users {
  constructor() {
    this.nextID = 3;
    this.users = [
      {
        id: 0,
        name: 'zero',
        email: 'zero@example.com',
        role: 'Admin',
        ...this.genSaltHashPassword('password'),
      },
      {
        id: 1,
        name: 'one',
        email: 'one@example.com',
        role: 'Student',
        ...this.genSaltHashPassword('password'),
      },
      {
        id: 2,
        name: 'prof',
        email: 'admin@example.com',
        role: 'Faculty',
        ...this.genSaltHashPassword('password'),
      },
    ];
  }

  /**
   * See https://ciphertrick.com/2016/01/18/salt-hash-passwords-using-nodejs-crypto/
   * generates random string of characters i.e salt
   * @function
   * @param {number} length - Length of the random string.
   */
  genRandomString = length => {
    return crypto
      .randomBytes(Math.ceil(length / 2))
      .toString('hex') /** convert to hexadecimal format */
      .slice(0, length); /** return required number of characters */
  };

  sha512 = (password, salt) => {
    var hash = crypto.createHmac(
      'sha512',
      salt,
    ); /** Hashing algorithm sha512 */
    hash.update(password);
    var value = hash.digest('hex');
    return {
      salt: salt,
      passwordHash: value,
    };
  };

  genSaltHashPassword = userpassword => {
    var salt = this.genRandomString(16); /** Gives us salt of length 16 */
    var passwordData = this.sha512(userpassword, salt);
    console.log('UserPassword = ' + userpassword);
    console.log('Passwordhash = ' + passwordData.passwordHash);
    console.log('nSalt = ' + passwordData.salt);
    return passwordData;
  };

  login(emailAddress, password) {
    // does a user with the specified emailAddress exist?
    const i = this.users.findIndex(({ email }) => email === emailAddress);
    if (i === -1) {
      throw new AuthenticationError('User not Found');
    }

    const user = this.users[i];

    // hash the password with the user salt
    const hashedPassword = this.sha512(password, user.salt).passwordHash;

    // compare the hashed password against the one in the user record
    if (hashedPassword !== user.passwordHash) {
      console.log(hashedPassword);
      console.log(user);
      throw new AuthenticationError('Bad Login or Password');
    }

    // create a jwt token and store
    //
    return {
      user: _.omit(user, ['passwordHash', 'salt']),
      token: userSessions.createSession(user.id, APP_SECRET),
    };
  }

  getUsers() {
    return this.users;
  }

  getStudents() {
    return this.users.filter(u => u.role === 'Student');
  }

  getStudentByEmail(email) {
    return this.getStudents().filter(s => s.email === email)[0] || null;
  }

  list() {
    return this.users;
  }

  get(id) {
    return this.users[id];
  }

  create(args) {
    const u = { name: args.name, id: this.nextID };
    this.users.push(u);
    this.nextID++;
    return u;
  }

  update(id, user) {
    const u = this.get({ id });

    u.name = user.name;
    return u;
  }
}

const users = new Users();
const userSessions = new UserSessions();

// Middleware function to authenticate and authorize the user
// Takes a resolver function and returns an adorned resolver
// that authenticates the user and then checks whether the
// user is permitted to perform the action in specified resolver.
// Options is a an object with two keys, both of which can
// be omitted.
// The two keys are:
//   requireUser: does the operation require the user to be logged
//     in? Defaults to true if not supplied
//   roles: array which specifies which user roles allow this operation
//
const makeResolver = (resolver, options) => {
  // return an adorned resolver function
  return (root, args, context, info) => {
    const o = {
      requireUser: true,
      roles: ['Admin', 'Student', 'Faculty'],
      ...options,
    };
    const { requireUser } = o;
    const { roles } = o;
    let user = null;
    let sessionID = null;

    if (requireUser) {
      // get the token from the request
      const token = context.req.headers.authorization || '';
      if (!token) {
        throw new AuthenticationError('Token Required');
      }

      // retrieve the user given the token
      [user, sessionID] = getUserForToken(token);
      if (!user) {
        throw new AuthenticationError('Invalid Token or User');
      }

      // authorize the operation for the user
      const userRole = user.role;
      if (_.indexOf(roles, userRole) === -1) {
        throw new ForbiddenError('Operation Not Permitted');
      }
    }

    // call the passed resolver with context extended with user
    return resolver(
      root,
      args,
      { ...context, user: user, sessionID: sessionID },
      info,
    );
  };
};

const resolvers = {
  Query: {
    users: makeResolver((root, args, context, info) => users.getUsers()),
    currentUser: makeResolver((root, args, context) => context.user),
    students: makeResolver((root, args, context, info) => users.getStudents()),
  },
  Mutation: {
    loginUser: makeResolver(
      (root, args, context, info) => {
        return users.login(args.email, args.password);
      },
      { requireUser: false },
    ),
    logoutUser: makeResolver((root, args, context, info) => {
      const sessionID = context.sessionID;
      userSessions.invalidateSession(sessionID);
      return true;
    }),
  },
  User: {
    __resolveType: (user, context, info) => user.role,
  },
  Student: {
    courses: student => {
      console.log('courses called');
      console.log(student);
      return [{ id: 0, name: 'course' }];
    },
  },
  Course: {
    professor: course => {
      console.log('course professor');
      return users.get(2);
    },
  },
};

const getUserForToken = token => {
  try {
    const { id, sessionID } = jwt.verify(token, APP_SECRET);
    const user = users.get(id);

    // get the user session
    // note: a better way to do this with a database is to
    // join the Users table with the UserSessions table on
    // users.id = user_sessions.user_id where session_id = sessionID
    // this would get both the user and the sessionID in one query
    const session = userSessions.getSession(sessionID);
    if (!session) {
      // If the session doesn't exist, it's been invalidated
      throw new AuthenticationError('Invalid Session');
    }

    return [user, session.id];
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      // invalidate the sesssion if expired
      const { sessionID } = jwt.decode(token);
      userSessions.invalidateSession(sessionID);
      throw new AuthenticationError('Session Expired');
    }
    throw new AuthenticationError('Bad Token');
  }
};

const server = new ApolloServer({
  typeDefs,
  resolvers,
  context: request => {
    return request;
  },
});

server.listen().then(({ url }) => {
  console.log(`🚀 Server ready at ${url}`);
});
