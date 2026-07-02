import { useEffect, useMemo, useState } from "react";
import { AbiCoder, hexlify, isHexString, keccak256, randomBytes } from "ethers";
import { chains, ZERO_HASH } from "./config/chains";
import { operations, timelockAbis, type OperationDef, type ParamDef } from "./config/operations";
import {
  decodeFunctionData,
  encodeFunctionData,
  formatDecodedValue,
  toEncodeArgs,
  type ValidatorInput,
} from "./lib/abi";

type FormState = Record<string, string | boolean | ValidatorInput[]>;
type TimelockMode = "schedule" | "execute" | "cancel";
type InteractionMode = "encode" | "decode";
type DisplayRow = { label: string; value: string; copyable?: boolean };

const initialValidatorRows = (): ValidatorInput[] => [
  { signer: "", power: "" },
  { signer: "", power: "" },
  { signer: "", power: "" },
];

const randomTimelockSalt = () => hexlify(randomBytes(32));

const buildInitialFormState = (operation: OperationDef): FormState =>
  Object.fromEntries(
    operation.params.map((param) => {
      if (param.kind === "bool") {
        return [param.name, false];
      }
      if (param.kind === "roleHashSelect") {
        return [param.name, param.options?.[0]?.value ?? ""];
      }
      if (param.kind === "validatorTupleArray") {
        return [param.name, initialValidatorRows()];
      }
      return [param.name, ""];
    }),
  );

const copy = async (value: string) => {
  await navigator.clipboard.writeText(value);
};

const hashTimelockOperation = (
  target: string,
  value: string,
  data: string,
  predecessor: string,
  salt: string,
) =>
  keccak256(
    AbiCoder.defaultAbiCoder().encode(
      ["address", "uint256", "bytes", "bytes32", "bytes32"],
      [target, value, data, predecessor, salt],
    ),
  );

const formatInputValue = (value: unknown) => formatDecodedValue(value);

const rowsFromOperationArgs = (operation: OperationDef, args: unknown[]): DisplayRow[] =>
  operation.params.map((param, index) => ({
    label: param.name,
    value: formatInputValue(args[index]),
    copyable: true,
  }));

const timelockAbiForAction = (action: TimelockMode) => {
  if (action === "schedule") {
    return timelockAbis.schedule;
  }
  if (action === "execute") {
    return timelockAbis.execute;
  }
  return timelockAbis.cancel;
};

const App = () => {
  const [chainId, setChainId] = useState(chains[0].id);
  const [operationId, setOperationId] = useState(operations[0].id);
  const [interactionMode, setInteractionMode] = useState<InteractionMode>("encode");
  const [timelockAction, setTimelockAction] = useState<TimelockMode>("schedule");
  const [timelockSalt, setTimelockSalt] = useState(randomTimelockSalt);
  const [cancelOperationId, setCancelOperationId] = useState("");
  const [decodeInput, setDecodeInput] = useState("");
  const [generatedRows, setGeneratedRows] = useState<DisplayRow[]>([]);
  const [lastError, setLastError] = useState("");
  const [copyNotice, setCopyNotice] = useState("");
  const [formState, setFormState] = useState<FormState>(() => buildInitialFormState(operations[0]));

  const chain = useMemo(() => chains.find((item) => item.id === chainId) ?? chains[0], [chainId]);
  const operation = useMemo(
    () => operations.find((item) => item.id === operationId) ?? operations[0],
    [operationId],
  );
  const isTimelocked = operation.mode === "timelock";
  const activeTimelock =
    operation.timelockType === "admin" ? chain.adminTimelock : chain.governanceTimelock;
  const timelockTarget = activeTimelock.address;
  const timelockBadge = isTimelocked
    ? `timelock:${Math.round(activeTimelock.delaySeconds / 3600)}h`
    : "direct";
  const operationModeBadge = (item: OperationDef) => {
    if (item.mode === "direct") {
      return "direct";
    }
    const itemTimelock =
      item.timelockType === "admin" ? chain.adminTimelock : chain.governanceTimelock;
    return `timelock:${Math.round(itemTimelock.delaySeconds / 3600)}h`;
  };

  useEffect(() => {
    if (!copyNotice) {
      return undefined;
    }
    const timer = window.setTimeout(() => setCopyNotice(""), 1800);
    return () => window.clearTimeout(timer);
  }, [copyNotice]);

  const handleCopy = async (value: string, label: string) => {
    await copy(value);
    setCopyNotice(label);
  };

  const resetForOperation = (nextOperation: OperationDef) => {
    setOperationId(nextOperation.id);
    setInteractionMode("encode");
    setTimelockAction("schedule");
    setTimelockSalt(randomTimelockSalt());
    setCancelOperationId("");
    setGeneratedRows([]);
    setDecodeInput("");
    setLastError("");
    setFormState(buildInitialFormState(nextOperation));
  };

  const handleFieldChange = (param: ParamDef, value: string | boolean) => {
    setFormState((current) => ({ ...current, [param.name]: value }));
  };

  const handleValidatorChange = (
    paramName: string,
    index: number,
    key: keyof ValidatorInput,
    value: string,
  ) => {
    setFormState((current) => {
      const rows = (current[paramName] as ValidatorInput[]) ?? initialValidatorRows();
      const next = rows.map((row, rowIndex) =>
        rowIndex === index ? { ...row, [key]: value } : row,
      );
      return { ...current, [paramName]: next };
    });
  };

  const addValidatorRow = (paramName: string) => {
    setFormState((current) => {
      const rows = (current[paramName] as ValidatorInput[]) ?? [];
      return { ...current, [paramName]: [...rows, { signer: "", power: "" }] };
    });
  };

  const removeValidatorRow = (paramName: string, index: number) => {
    setFormState((current) => {
      const rows = (current[paramName] as ValidatorInput[]) ?? [];
      const next = rows.filter((_, rowIndex) => rowIndex !== index);
      return { ...current, [paramName]: next.length > 0 ? next : initialValidatorRows() };
    });
  };

  const buildDirectRows = (
    operationArgs: unknown[],
  ): DisplayRow[] => [
    { label: "To Address", value: chain.vaultProxy, copyable: true },
    { label: "ETH Value", value: "0", copyable: true },
    { label: "ABI", value: operation.abiJson, copyable: true },
    ...rowsFromOperationArgs(operation, operationArgs),
  ];

  const buildTimelockRows = (
    businessCalldata: string,
    operationArgs: unknown[],
    salt: string,
  ): DisplayRow[] => {
    const operationIdHash = hashTimelockOperation(
      chain.vaultProxy,
      "0",
      businessCalldata,
      ZERO_HASH,
      salt,
    );

    if (timelockAction === "cancel") {
      return [
        { label: "To Address", value: timelockTarget, copyable: true },
        { label: "ETH Value", value: "0", copyable: true },
        { label: "ABI", value: timelockAbis.cancel, copyable: true },
        { label: "id", value: operationIdHash, copyable: true },
        ...rowsFromOperationArgs(operation, operationArgs),
      ];
    }

    return [
      { label: "To Address", value: timelockTarget, copyable: true },
      { label: "ETH Value", value: "0", copyable: true },
      { label: "ABI", value: timelockAbiForAction(timelockAction), copyable: true },
      { label: "target", value: chain.vaultProxy, copyable: true },
      { label: "value", value: "0", copyable: true },
      { label: "data", value: businessCalldata, copyable: true },
      { label: "predecessor", value: ZERO_HASH, copyable: true },
      { label: "salt", value: salt, copyable: true },
      ...(timelockAction === "schedule"
        ? [{ label: "delay", value: String(activeTimelock.delaySeconds), copyable: true }]
        : []),
      { label: "operation id", value: operationIdHash, copyable: true },
    ];
  };

  const handleGenerate = () => {
    try {
      if (isTimelocked && timelockAction === "cancel") {
        const id = cancelOperationId.trim();
        if (!isHexString(id, 32)) {
          throw new Error("Operation id must be a 32-byte hex value.");
        }
        setGeneratedRows([
          { label: "To Address", value: timelockTarget, copyable: true },
          { label: "ETH Value", value: "0", copyable: true },
          { label: "ABI", value: timelockAbis.cancel, copyable: true },
          { label: "id", value: id, copyable: true },
        ]);
        setLastError("");
        return;
      }

      const operationArgs = toEncodeArgs(operation.params, formState);
      const businessCalldata = encodeFunctionData(
        operation.abiJson,
        operation.functionName,
        operationArgs,
      );
      const nextSalt = isTimelocked && timelockAction === "schedule" ? randomTimelockSalt() : timelockSalt;
      setTimelockSalt(nextSalt);
      setGeneratedRows(
        isTimelocked
          ? buildTimelockRows(businessCalldata, operationArgs, nextSalt)
          : buildDirectRows(operationArgs),
      );
      setLastError("");
    } catch (error) {
      setGeneratedRows([]);
      setLastError(error instanceof Error ? error.message : "Failed to generate parameters.");
    }
  };

  const decodeResult = useMemo(() => {
    if (!decodeInput.trim()) {
      return { rows: [] as DisplayRow[], error: "" };
    }

    try {
      if (!isTimelocked) {
        const decoded = decodeFunctionData(
          operation.abiJson,
          operation.functionName,
          decodeInput.trim(),
        );
        return {
          rows: [
            { label: "To Address", value: chain.vaultProxy, copyable: true },
            ...operation.params.map((param, index) => ({
              label: param.name,
              value: formatDecodedValue(decoded[index]),
              copyable: true,
            })),
          ],
          error: "",
        };
      }

      if (timelockAction === "cancel") {
        const decoded = decodeFunctionData(timelockAbis.cancel, "cancel", decodeInput.trim());
        return {
          rows: [
            { label: "To Address", value: timelockTarget, copyable: true },
            { label: "id", value: formatDecodedValue(decoded[0]), copyable: true },
          ],
          error: "",
        };
      }

      const abiJson = timelockAction === "schedule" ? timelockAbis.schedule : timelockAbis.execute;
      const decoded = decodeFunctionData(abiJson, timelockAction, decodeInput.trim());
      const data = String(decoded[2]);
      const salt = String(decoded[4]);
      const operationIdHash = hashTimelockOperation(
        String(decoded[0]),
        String(decoded[1]),
        data,
        String(decoded[3]),
        salt,
      );
      const rows: DisplayRow[] = [
        { label: "To Address", value: timelockTarget, copyable: true },
        { label: "target", value: formatDecodedValue(decoded[0]), copyable: true },
        { label: "value", value: formatDecodedValue(decoded[1]), copyable: true },
        { label: "data", value: data, copyable: true },
        { label: "predecessor", value: formatDecodedValue(decoded[3]), copyable: true },
        { label: "salt", value: salt, copyable: true },
        ...(timelockAction === "schedule"
          ? [{ label: "delay", value: formatDecodedValue(decoded[5]), copyable: true }]
          : []),
        { label: "operation id", value: operationIdHash, copyable: true },
      ];

      try {
        const innerDecoded = decodeFunctionData(operation.abiJson, operation.functionName, data);
        rows.push(
          ...operation.params.map((param, index) => ({
            label: param.name,
            value: formatDecodedValue(innerDecoded[index]),
            copyable: true,
          })),
        );
      } catch {
        rows.push({
          label: "data decode",
          value: "Cannot decode data with the selected operation ABI.",
        });
      }

      return { rows, error: "" };
    } catch (error) {
      return {
        rows: [] as DisplayRow[],
        error: error instanceof Error ? error.message : "Failed to decode calldata.",
      };
    }
  }, [chain.vaultProxy, decodeInput, isTimelocked, operation, timelockAction, timelockTarget]);

  return (
    <div className="shell compact-shell">
      <div className="glow glow-a" />
      <div className="glow glow-b" />

      <header className="hero compact-hero">
        <div className="hero-copy-block">
          <p className="eyebrow">AssetVault Ops</p>
          <h1>Safe parameters generator</h1>
          <p className="hero-copy">
            Fill only the required business fields, then copy the exact fields needed in Safe.
          </p>
        </div>
      </header>

      <main className="flow-layout">
        <section className="panel flow-panel">
          <div className="section-heading inline-head">
            <div>
              <h2>1. Select chain</h2>
              <p>Target addresses are fixed per chain.</p>
            </div>
          </div>
          <div className="chain-layout">
            <div className="chain-list">
              {chains.map((item) => (
                <button
                  key={item.id}
                  className={`chain-chip ${item.id === chain.id ? "active" : ""}`}
                  onClick={() => setChainId(item.id)}
                  type="button"
                >
                  <strong>{item.name}</strong>
                  <small>Chain ID {item.chainId}</small>
                </button>
              ))}
            </div>

            <div className="chain-info-compact">
              <p>
                <span>vault:</span>
                <code>{chain.vaultProxy}</code>
              </p>
              <p>
                <span>admin timelock:</span>
                <code>{chain.adminTimelock.address}</code>
              </p>
              <p>
                <span>governance timelock:</span>
                <code>{chain.governanceTimelock.address}</code>
              </p>
              <small>{chain.addressNote}</small>
            </div>
          </div>
        </section>

        <section className="panel flow-panel">
          <div className="section-heading">
            <div>
              <h2>2. Select operation</h2>
              <p>Select the function and whether you want to generate or decode parameters.</p>
            </div>
          </div>

          <div className="ops-list compact centered">
            {operations.map((item) => (
              <button
                key={item.id}
                className={`op-chip ${item.id === operation.id ? "active" : ""}`}
                onClick={() => resetForOperation(item)}
                type="button"
              >
                <span>{item.label}</span>
                <div className="op-badges">
                  <small>{item.role}</small>
                  <small>{operationModeBadge(item)}</small>
                </div>
              </button>
            ))}
          </div>

          <div className="mode-row">
            <div className="segmented">
              <button
                type="button"
                className={interactionMode === "encode" ? "active" : ""}
                onClick={() => {
                  setInteractionMode("encode");
                  setLastError("");
                }}
              >
                Generate parameters
              </button>
              <button
                type="button"
                className={interactionMode === "decode" ? "active" : ""}
                onClick={() => {
                  setInteractionMode("decode");
                  setLastError("");
                }}
              >
                Decode calldata
              </button>
            </div>
          </div>

          <div className="operation-summary stacked">
            <div className="summary-head">
              <div>
                <p className="eyebrow">Current operation</p>
                <h2>{operation.label}</h2>
                <p className="operation-copy">{operation.description}</p>
              </div>
              <div className="badge-stack">
                <span className="badge">{operation.role}</span>
                <span className="badge soft">{timelockBadge}</span>
              </div>
            </div>
          </div>
        </section>

        <section className="panel flow-panel">
          <div className="section-heading">
            <h2>3. {interactionMode === "encode" ? "Required fields" : "Input calldata"}</h2>
            <p>
              {interactionMode === "encode"
                ? "Only fill the business function fields. Timelock predecessor, salt, and delay are handled below."
                : "Paste calldata. ABI JSON is intentionally hidden; decoding uses the selected function."}
            </p>
          </div>

          {isTimelocked ? (
            <div className="timelock-action-row">
              <span>Timelock action</span>
              <div className="segmented">
                <button
                  type="button"
                  className={timelockAction === "schedule" ? "active" : ""}
                  onClick={() => setTimelockAction("schedule")}
                >
                  schedule
                </button>
                <button
                  type="button"
                  className={timelockAction === "execute" ? "active" : ""}
                  onClick={() => setTimelockAction("execute")}
                >
                  execute
                </button>
                <button
                  type="button"
                  className={timelockAction === "cancel" ? "active" : ""}
                  onClick={() => setTimelockAction("cancel")}
                >
                  cancel
                </button>
              </div>
            </div>
          ) : null}

          {interactionMode === "encode" ? (
            <div className="compact-stack">
              {isTimelocked && timelockAction === "cancel" ? (
                <div className="cancel-picker">
                  <label className="field">
                    <span>id</span>
                    <input
                      value={cancelOperationId}
                      onChange={(event) => setCancelOperationId(event.target.value)}
                      placeholder="Timelock operation id: 0x..."
                    />
                    <small>Paste the operation id from the approval record or schedule event.</small>
                  </label>
                </div>
              ) : (
                <div className="form-grid compact">
                  {operation.params.map((param) => (
                    <ParamField
                      key={param.name}
                      param={param}
                      value={formState[param.name]}
                      onChange={handleFieldChange}
                      onValidatorChange={handleValidatorChange}
                      onAddValidatorRow={addValidatorRow}
                      onRemoveValidatorRow={removeValidatorRow}
                    />
                  ))}
                </div>
              )}

              <button className="primary-action compact-action" type="button" onClick={handleGenerate}>
                Generate parameters
              </button>
              {isTimelocked && timelockAction === "execute" ? (
                <p className="hint-text">
                  Execute uses the retained salt from schedule. Generate schedule first and reuse the
                  shown salt / operation id for later execution.
                </p>
              ) : null}
            </div>
          ) : (
            <div className="compact-stack">
              <label className="field field-full">
                <span>Calldata</span>
                <textarea
                  rows={6}
                  value={decodeInput}
                  onChange={(event) => setDecodeInput(event.target.value)}
                  placeholder="0x..."
                />
              </label>
            </div>
          )}

          {lastError ? <p className="error-text">{lastError}</p> : null}
          {decodeResult.error ? <p className="error-text">{decodeResult.error}</p> : null}
        </section>

        <section className="panel flow-panel">
          <div className="section-heading">
            <h2>4. {interactionMode === "encode" ? "Safe fields to copy" : "Decoded parameters"}</h2>
            <p>
              {interactionMode === "encode"
                ? "These are display-only fields. Copy them one by one into the Safe interface."
                : "Decoded values are shown directly from the selected ABI."}
            </p>
          </div>

          {interactionMode === "encode" ? (
            <DisplayRows
              rows={generatedRows}
              emptyText="Fill the required fields and click Generate parameters."
              onCopy={handleCopy}
            />
          ) : (
            <DisplayRows
              rows={decodeResult.rows}
              emptyText="Paste calldata to decode parameters."
              onCopy={handleCopy}
            />
          )}
        </section>
      </main>

      {copyNotice ? <div className="copy-toast">{copyNotice}</div> : null}
    </div>
  );
};

type ParamFieldProps = {
  param: ParamDef;
  value: string | boolean | ValidatorInput[];
  onChange: (param: ParamDef, value: string | boolean) => void;
  onValidatorChange: (paramName: string, index: number, key: keyof ValidatorInput, value: string) => void;
  onAddValidatorRow: (paramName: string) => void;
  onRemoveValidatorRow: (paramName: string, index: number) => void;
};

const ParamField = ({
  param,
  value,
  onChange,
  onValidatorChange,
  onAddValidatorRow,
  onRemoveValidatorRow,
}: ParamFieldProps) => {
  if (param.kind === "bool") {
    return (
      <label className="field">
        <span>{param.label}</span>
        <select
          value={String(Boolean(value))}
          onChange={(event) => onChange(param, event.target.value === "true")}
        >
          <option value="false">false</option>
          <option value="true">true</option>
        </select>
      </label>
    );
  }

  if (param.kind === "roleHashSelect") {
    return (
      <label className="field">
        <span>{param.label}</span>
        <select
          value={String(value)}
          onChange={(event) => onChange(param, event.target.value)}
        >
          {(param.options ?? []).map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </label>
    );
  }

  if (param.kind === "validatorTupleArray") {
    const rows = value as ValidatorInput[];
    return (
      <div className="validator-field field-full">
        <div className="validator-head">
          <div>
            <span>{param.label}</span>
            {param.help ? <small>{param.help}</small> : null}
          </div>
          <button type="button" className="mini-button" onClick={() => onAddValidatorRow(param.name)}>
            Add Row
          </button>
        </div>
        <div className="validator-table">
          {rows.map((row, index) => (
            <div className="validator-row" key={`${param.name}-${index}`}>
              <input
                value={row.signer}
                onChange={(event) => onValidatorChange(param.name, index, "signer", event.target.value)}
                placeholder="Signer address"
              />
              <input
                value={row.power}
                onChange={(event) => onValidatorChange(param.name, index, "power", event.target.value)}
                placeholder="Power"
              />
              <button type="button" className="danger-button" onClick={() => onRemoveValidatorRow(param.name, index)}>
                Remove
              </button>
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (param.kind === "address[]") {
    return (
      <label className="field field-full">
        <span>{param.label}</span>
        <textarea
          rows={5}
          value={String(value)}
          onChange={(event) => onChange(param, event.target.value)}
          placeholder={param.placeholder}
        />
        {param.help ? <small>{param.help}</small> : null}
      </label>
    );
  }

  if (param.kind === "bytes") {
    return (
      <label className="field field-full">
        <span>{param.label}</span>
        <textarea
          rows={4}
          value={String(value)}
          onChange={(event) => onChange(param, event.target.value)}
          placeholder={param.placeholder}
        />
        {param.help ? <small>{param.help}</small> : null}
      </label>
    );
  }

  return (
    <label className="field">
      <span>{param.label}</span>
      <input
        value={String(value)}
        onChange={(event) => onChange(param, event.target.value)}
        placeholder={param.placeholder}
      />
      {param.help ? <small>{param.help}</small> : null}
    </label>
  );
};

const DisplayRows = ({
  rows,
  emptyText,
  onCopy,
}: {
  rows: DisplayRow[];
  emptyText: string;
  onCopy: (value: string, label: string) => Promise<void>;
}) => {
  if (rows.length === 0) {
    return <p className="empty-state">{emptyText}</p>;
  }
  return (
    <div className="decoded-list safe-field-list">
      {rows.map((row, index) => (
        <div className="decoded-row safe-field-row" key={`${row.label}-${index}`}>
          <div className="meta-head">
            <span>{row.label}</span>
            {row.copyable ? (
              <button
                type="button"
                className="mini-button icon-button"
                onClick={() => onCopy(row.value, `${row.label} copied`)}
              >
                <CopyIcon />
                Copy
              </button>
            ) : null}
          </div>
          <pre>{row.value}</pre>
        </div>
      ))}
    </div>
  );
};

export default App;

const CopyIcon = () => (
  <svg
    aria-hidden="true"
    className="copy-icon"
    viewBox="0 0 16 16"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
  >
    <path
      d="M5.5 2.5H11.5C12.0523 2.5 12.5 2.94772 12.5 3.5V11.5C12.5 12.0523 12.0523 12.5 11.5 12.5H5.5C4.94772 12.5 4.5 12.0523 4.5 11.5V3.5C4.5 2.94772 4.94772 2.5 5.5 2.5Z"
      stroke="currentColor"
      strokeWidth="1.2"
    />
    <path
      d="M3.5 10.5H3C2.44772 10.5 2 10.0523 2 9.5V2.99999C2 2.44771 2.44772 1.99999 3 1.99999H9.5C10.0523 1.99999 10.5 2.44771 10.5 2.99999V3.5"
      stroke="currentColor"
      strokeWidth="1.2"
      strokeLinecap="round"
    />
  </svg>
);
