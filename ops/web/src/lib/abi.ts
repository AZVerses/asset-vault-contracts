import { Interface, isAddress, zeroPadValue } from "ethers";
import type { ParamDef } from "../config/operations";

export type ValidatorInput = {
  signer: string;
  power: string;
};

export const normalizeHex = (value: string) => {
  const trimmed = value.trim();
  return trimmed === "" ? "0x" : trimmed;
};

export const ensureBytes32 = (value: string) => {
  const trimmed = value.trim();
  return zeroPadValue(trimmed, 32);
};

export const parseAddressArray = (value: string) =>
  value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);

export const parseValidators = (rows: ValidatorInput[]) =>
  rows
    .filter((row) => row.signer.trim() !== "" || row.power.trim() !== "")
    .map((row) => ({
      signer: row.signer.trim(),
      power: row.power.trim(),
    }));

export const validateParamValue = (
  param: ParamDef,
  rawValue: string | boolean | ValidatorInput[],
) => {
  if (param.kind === "bool") {
    return;
  }

  if (param.kind === "roleHashSelect") {
    const value = String(rawValue).trim();
    if (!value) {
      throw new Error(`${param.label} is required.`);
    }
    return;
  }

  if (param.kind === "validatorTupleArray") {
    const rows = rawValue as ValidatorInput[];
    const validators = parseValidators(rows);
    if (validators.length === 0) {
      throw new Error(`${param.label} is required.`);
    }
    validators.forEach((validator, index) => {
      if (!isAddress(validator.signer)) {
        throw new Error(`Validator ${index + 1} signer is not a valid address.`);
      }
      if (validator.power.trim() === "") {
        throw new Error(`Validator ${index + 1} power is required.`);
      }
    });
    return;
  }

  const value = String(rawValue).trim();
  if (!value) {
    throw new Error(`${param.label} is required.`);
  }
  if (param.kind === "address" && !isAddress(value)) {
    throw new Error(`${param.label} is not a valid address.`);
  }
  if (param.kind === "address[]") {
    const addresses = parseAddressArray(value);
    if (addresses.length === 0) {
      throw new Error(`${param.label} requires at least one address.`);
    }
    addresses.forEach((address, index) => {
      if (!isAddress(address)) {
        throw new Error(`${param.label} item ${index + 1} is not a valid address.`);
      }
    });
  }
};

export const encodeFunctionData = (
  abiJson: string,
  functionName: string,
  args: unknown[],
) => {
  const iface = new Interface(abiJson);
  return iface.encodeFunctionData(functionName, args);
};

export const decodeFunctionData = (
  abiJson: string,
  functionName: string,
  calldata: string,
) => {
  const iface = new Interface(abiJson);
  return iface.decodeFunctionData(functionName, calldata);
};

export const toEncodeArgs = (
  params: ParamDef[],
  values: Record<string, string | boolean | ValidatorInput[]>,
) =>
  params.map((param) => {
    const rawValue = values[param.name];
    validateParamValue(param, rawValue);

    switch (param.kind) {
      case "address":
        return String(rawValue).trim();
      case "uint256":
        return String(rawValue).trim();
      case "bool":
        return Boolean(rawValue);
      case "roleHashSelect":
        return String(rawValue).trim();
      case "bytes":
        return normalizeHex(String(rawValue));
      case "bytes32":
        return ensureBytes32(String(rawValue));
      case "address[]":
        return parseAddressArray(String(rawValue));
      case "validatorTupleArray":
        return parseValidators(rawValue as ValidatorInput[]);
      default:
        return rawValue;
    }
  });

export const formatDecodedValue = (value: unknown): string => {
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "string") {
    return value;
  }
  if (Array.isArray(value)) {
    return JSON.stringify(value.map((item) => serializeDecoded(item)), null, 2);
  }
  return JSON.stringify(serializeDecoded(value), null, 2);
};

const serializeDecoded = (value: unknown): unknown => {
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (Array.isArray(value)) {
    return value.map((item) => serializeDecoded(item));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([key]) => Number.isNaN(Number(key)))
        .map(([key, inner]) => [key, serializeDecoded(inner)]),
    );
  }
  return value;
};
