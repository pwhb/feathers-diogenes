// For more information about this file see https://dove.feathersjs.com/guides/cli/service.class.html#database-services
import type { Params } from '@feathersjs/feathers'
import { MongoDBService } from '@feathersjs/mongodb'
import type { MongoDBAdapterParams, MongoDBAdapterOptions } from '@feathersjs/mongodb'

import type { Application } from '../../declarations'
import type { Message, MessageData, MessagePatch, MessageQuery } from './messages.schema'

export type { Message, MessageData, MessagePatch, MessageQuery }

export interface MessageParams extends MongoDBAdapterParams<MessageQuery> {}

// By default calls the standard MongoDB adapter service methods but can be customized with your own functionality.
export class MessageService<ServiceParams extends Params = MessageParams> extends MongoDBService<
  Message,
  MessageData,
  MessageParams,
  MessagePatch
> {}

export const getOptions = (app: Application): MongoDBAdapterOptions => {
  return {
    paginate: app.get('paginate'),
    Model: app.get('mongodbClient').then((db) => db.collection('messages'))
  }
}
