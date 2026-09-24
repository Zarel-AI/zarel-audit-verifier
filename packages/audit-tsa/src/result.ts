// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nicolas Moreno
/**
 * Minimal `Result` for fallible operations — inlined so this verifier library
 * carries no dependency for it. The shape is the tagged union
 * `{ _tag: 'Ok', value } | { _tag: 'Err', error }`, so a value produced here flows
 * through any consumer whose own `Result` has that shape (structural typing).
 * Only the `ok`/`err` constructors + the type are needed.
 */

export interface Ok<T> {
    readonly _tag: 'Ok';
    readonly value: T;
}

export interface Err<E> {
    readonly _tag: 'Err';
    readonly error: E;
}

export type Result<T, E> = Ok<T> | Err<E>;

export function ok<T>(value: T): Ok<T> {
    return { _tag: 'Ok', value };
}

export function err<E>(error: E): Err<E> {
    return { _tag: 'Err', error };
}
