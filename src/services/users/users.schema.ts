// // For more information about this file see https://dove.feathersjs.com/guides/cli/service.schemas.html
import { resolve } from '@feathersjs/schema';
import { Type, getValidator, querySyntax } from '@feathersjs/typebox';
import { ObjectIdSchema } from '@feathersjs/typebox';
import type { Static } from '@feathersjs/typebox';
import { passwordHash } from '@feathersjs/authentication-local';
import { createHash } from 'crypto';

import type { HookContext } from '../../declarations';
import { dataValidator, queryValidator } from '../../validators';

// Main data model schema
export const userSchema = Type.Object(
  {
    _id: ObjectIdSchema(),
    username: Type.String(),
    password: Type.String(),
    avatar: Type.Optional(Type.String()),
    createdAt: Type.Number(),
    updatedAt: Type.Number()
  },
  { $id: 'User', additionalProperties: false }
);
export type User = Static<typeof userSchema>;
export const userValidator = getValidator(userSchema, dataValidator);
export const userResolver = resolve<User, HookContext>({});

export const userExternalResolver = resolve<User, HookContext>({
  // The password should never be visible externally
  password: async () => undefined
});

// Schema for creating new entries
export const userDataSchema = Type.Pick(userSchema, ['username', 'password', 'avatar'], {
  $id: 'UserData'
});
export type UserData = Static<typeof userDataSchema>;
export const userDataValidator = getValidator(userDataSchema, dataValidator);
export const userDataResolver = resolve<User, HookContext>({
  password: passwordHash({ strategy: 'local' }),
  avatar: async (value, user) =>
  {
    // If the user passed an avatar image, use it
    if (value !== undefined)
    {
      return value;
    }

    // Gravatar uses MD5 hashes from an email address to get the image
    const hash = createHash('md5').update(user.username.toLowerCase()).digest('hex');
    // Return the full avatar URL
    return `https://s.gravatar.com/avatar/${hash}?s=60`;
  },
  createdAt: async () => new Date().getTime(),
  updatedAt: async () => new Date().getTime()
});

// Schema for updating existing entries
export const userPatchSchema = Type.Partial(userSchema, {
  $id: 'UserPatch'
});
export type UserPatch = Static<typeof userPatchSchema>;
export const userPatchValidator = getValidator(userPatchSchema, dataValidator);
export const userPatchResolver = resolve<User, HookContext>({
  password: passwordHash({ strategy: 'local' })
});

// Schema for allowed query properties
export const userQueryProperties = Type.Pick(userSchema, ['_id', 'username']);
export const userQuerySchema = Type.Intersect(
  [
    querySyntax(userQueryProperties),
    // Add additional query properties here
    Type.Object({}, { additionalProperties: false })
  ],
  { additionalProperties: false }
);
export type UserQuery = Static<typeof userQuerySchema>;
export const userQueryValidator = getValidator(userQuerySchema, queryValidator);
export const userQueryResolver = resolve<UserQuery, HookContext>({
  // If there is a user (e.g. with authentication), they are only allowed to see their own data
  _id: async (value, user, context) =>
  {
    // We want to be able to get a list of all users but
    // only let a user modify their own data otherwise
    if (context.params.user && context.method !== 'find')
    {
      return context.params.user._id;
    }

    return value;
  }
});
