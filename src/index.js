import {
  ApolloServer,
  gql,
  AuthenticationError,
  ForbiddenError,
} from 'apollo-server';
import _ from 'lodash';
import bcrypt from 'bcryptjs';
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
    //    throw new AuthenticationError('No such user found');
    const i = this.users.findIndex(({ email }) => email === emailAddress);
    if (i === -1) {
      throw new AuthenticationError('User not Found');
    }

    const user = this.users[i];
    const hashedPassword = this.sha512(password, user.salt).passwordHash;

    if (hashedPassword !== user.passwordHash) {
      console.log(hashedPassword);
      console.log(user);
      throw new AuthenticationError('Bad Login or Password');
    }
    return {
      user: _.omit(this.users[i], ['passwordHash', 'salt']),
      token: jwt.sign({ id: user.id }, APP_SECRET, { expiresIn: 3 * 60 }),
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

// Provide resolver functions for your schema fields
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

    if (requireUser) {
      // get the token from the request
      const token = context.req.headers.authorization || '';
      if (!token) {
        throw new AuthenticationError('Token Required');
      }

      // retrieve the user given the token
      user = getUserForToken(token);
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
    return resolver(root, args, { ...context, user: user }, info);
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
      const user = context.user;
      return users.logout(user.id);
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
    const { id } = jwt.verify(token, APP_SECRET);
    const user = users.get(id);

    return user;
  } catch (error) {
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
