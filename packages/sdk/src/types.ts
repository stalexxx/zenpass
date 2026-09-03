// Re-exported wire types from @pass/contracts. The SDK adds no parallel
// type definitions for these shapes — @pass/contracts is the single
// source of truth for the wire format (per C02's brief: "Use these
// directly as your wire types").
export type {
  Id,
  Account,
  Device,
  Vault,
  ItemRecord,
  Mutation,
  ChangePage,
  Conflict,
  ApiError,
} from "@pass/contracts";

export interface Session {
  accessToken: string;
  expiresAt: string;
}
