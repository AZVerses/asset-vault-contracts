import { useEffect, useMemo, useState } from "react";
import { Interface } from "ethers";
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
type TimelockMode = "schedule" | "execute";
type InteractionMode = "encode" | "decode";

const initialValidatorRows = (): ValidatorInput[] => [
  { signer: "", power: "" },
  { signer: "", power: "" },
  { signer: "", power: "" },
];

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

const App = () => {
  const [chainId, setChainId] = useState(chains[0].id);
  const [operationId, setOperationId] = useState(operations[0].id);
  const [interactionMode, setInteractionMode] = useState<InteractionMode>("encode");
  const [timelockAction, setTimelockAction] = useState<TimelockMode>("schedule");
  const [timelockSalt, setTimelockSalt] = useState(ZERO_HASH);
  const [timelockPredecessor, setTimelockPredecessor] = useState(ZERO_HASH);
  const [decodeInput, setDecodeInput] = useState("");
  const [generatedCalldata, setGeneratedCalldata] = useState("");
  const [generatedTimelockCalldata, setGeneratedTimelockCalldata] = useState("");
  const [lastError, setLastError] = useState("");
  const [copyNotice, setCopyNotice] = useState("");
  const [formState, setFormState] = useState<FormState>(() => buildInitialFormState(operations[0]));

  const chain = useMemo(() => chains.find((item) => item.id === chainId) ?? chains[0], [chainId]);
  const operation = useMemo(
    () => operations.find((item) => item.id === operationId) ?? operations[0],
    [operationId],
  );
  const isTimelocked = operation.mode === "timelock";
  const timelockTarget =
    operation.timelockType === "admin" ? chain.adminTimelock : chain.governanceTimelock;
  const timelockLabel =
    operation.timelockType === "admin" ? "Admin Timelock" : "Governance Timelock";

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
    setTimelockSalt(ZERO_HASH);
    setTimelockPredecessor(ZERO_HASH);
    setGeneratedCalldata("");
    setGeneratedTimelockCalldata("");
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

  const handleGenerate = () => {
    try {
      const args = toEncodeArgs(operation.params, formState);
      const calldata = encodeFunctionData(operation.abiJson, operation.functionName, args);
      setGeneratedCalldata(calldata);
      setLastError("");

      if (isTimelocked) {
        const timelockIface = new Interface(
          timelockAction === "schedule" ? timelockAbis.schedule : timelockAbis.execute,
        );
        const timelockArgs =
          timelockAction === "schedule"
            ? [
                chain.vaultProxy,
                0,
                calldata,
                timelockPredecessor,
                timelockSalt,
                chain.timelockDelaySeconds,
              ]
            : [chain.vaultProxy, 0, calldata, timelockPredecessor, timelockSalt];
        setGeneratedTimelockCalldata(timelockIface.encodeFunctionData(timelockAction, timelockArgs));
      } else {
        setGeneratedTimelockCalldata("");
      }
    } catch (error) {
      setLastError(error instanceof Error ? error.message : "Failed to generate calldata.");
    }
  };

  const decodedDirectRows = useMemo(() => {
    if (operation.mode !== "direct" || !decodeInput.trim()) {
      return [];
    }
    try {
      const decoded = decodeFunctionData(operation.abiJson, operation.functionName, decodeInput.trim());
      setLastError("");
      return operation.params.map((param, index) => ({
        label: param.label,
        value: formatDecodedValue(decoded[index]),
      }));
    } catch (error) {
      setLastError(error instanceof Error ? error.message : "Failed to decode calldata.");
      return [];
    }
  }, [decodeInput, operation]);

  const decodedTimelockData = useMemo(() => {
    if (!isTimelocked || !decodeInput.trim()) {
      return null;
    }
    try {
      const abiJson = timelockAction === "schedule" ? timelockAbis.schedule : timelockAbis.execute;
      const decoded = decodeFunctionData(abiJson, timelockAction, decodeInput.trim());
      setLastError("");
      return decoded;
    } catch (error) {
      setLastError(error instanceof Error ? error.message : "Failed to decode Timelock calldata.");
      return null;
    }
  }, [decodeInput, isTimelocked, timelockAction]);

  const decodedTimelockRows = useMemo(() => {
    if (!decodedTimelockData) {
      return [];
    }
    const labels =
      timelockAction === "schedule"
        ? ["Target", "Value", "Data", "Predecessor", "Salt", "Delay"]
        : ["Target", "Value", "Data", "Predecessor", "Salt"];
    return labels.map((label, index) => ({
      label,
      value: formatDecodedValue(decodedTimelockData[index]),
    }));
  }, [decodedTimelockData, timelockAction]);

  const decodedInnerRows = useMemo(() => {
    if (!isTimelocked || !decodedTimelockData) {
      return [];
    }
    try {
      const innerCalldata = String(decodedTimelockData[2]);
      const decoded = decodeFunctionData(operation.abiJson, operation.functionName, innerCalldata);
      setLastError("");
      return operation.params.map((param, index) => ({
        label: param.label,
        value: formatDecodedValue(decoded[index]),
      }));
    } catch (error) {
      setLastError(error instanceof Error ? error.message : "Failed to decode inner business calldata.");
      return [];
    }
  }, [decodedTimelockData, isTimelocked, operation]);

  return (
    <div className="shell compact-shell">
      <div className="glow glow-a" />
      <div className="glow glow-b" />

      <header className="hero compact-hero">
        <div className="hero-copy-block">
          <p className="eyebrow">AssetVault Ops</p>
          <h1>Multisig calldata checker</h1>
          <p className="hero-copy">
            Review and verify whitelisted Safe calldata without local tooling.
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
          <div className="compact-stack">
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

            <div className="chain-info-grid">
              <div className="chain-info-item">
                <span>Vault Proxy</span>
                <code>{chain.vaultProxy}</code>
              </div>
              <div className="chain-info-item">
                <span>Admin Timelock</span>
                <code>{chain.adminTimelock}</code>
              </div>
              <div className="chain-info-item">
                <span>Governance Timelock</span>
                <code>{chain.governanceTimelock}</code>
              </div>
              <div className="chain-info-item">
                <span>Timelock Delay</span>
                <strong>{chain.timelockDelaySeconds}s</strong>
                <small>{chain.addressNote}</small>
              </div>
            </div>
          </div>
        </section>

        <section className="panel flow-panel">
          <div className="section-heading">
            <div>
              <h2>2. Select operation</h2>
              <p>Select a whitelisted operation and review the execution path.</p>
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
                <small>{item.role}</small>
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
                Encode
              </button>
              <button
                type="button"
                className={interactionMode === "decode" ? "active" : ""}
                onClick={() => {
                  setInteractionMode("decode");
                  setLastError("");
                }}
              >
                Decode
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
                <span className="badge soft">
                  {operation.mode === "direct" ? "Vault Proxy" : timelockLabel}
                </span>
              </div>
            </div>

            <div className="detail-grid compact single-row-info">
              <div className="detail-card compact">
                <span>Target</span>
                <strong>{chain.vaultProxy}</strong>
                <small>Vault Proxy</small>
              </div>
              {isTimelocked ? (
                <div className="detail-card compact">
                  <span>Outer Target</span>
                  <strong>{timelockTarget}</strong>
                  <small>{timelockLabel}</small>
                </div>
              ) : null}
              <div className="detail-card compact">
                <span>Function Signature</span>
                <strong>{operation.functionSignature}</strong>
                <small>{isTimelocked ? "Inner business function" : "Direct function"}</small>
              </div>
              {isTimelocked ? (
                <div className="detail-card compact">
                  <span>Delay</span>
                  <strong>{chain.timelockDelaySeconds}s</strong>
                  <small>OpenZeppelin TimelockController</small>
                </div>
              ) : null}
            </div>
          </div>
        </section>

        <section className="panel flow-panel">
          <div className="section-heading">
            <h2>3. {interactionMode === "encode" ? "Parameters" : "Input calldata"}</h2>
            <p>
              {interactionMode === "encode"
                ? "Fill parameters and generate calldata."
                : "Paste calldata and decode it with the selected interface."}
            </p>
          </div>

          {interactionMode === "encode" ? (
            <div className="compact-stack">
              <CodeBlock title="ABI JSON" value={operation.abiJson} onCopy={handleCopy} />

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

              {isTimelocked ? (
                <div className="timelock-box">
                  <div className="timelock-header">
                    <h3>Timelock wrapper</h3>
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
                    </div>
                  </div>
                  <CodeBlock
                    title={`${timelockAction} ABI JSON`}
                    value={timelockAction === "schedule" ? timelockAbis.schedule : timelockAbis.execute}
                    onCopy={handleCopy}
                  />
                  <div className="field-grid compact">
                    <label className="field">
                      <span>Predecessor</span>
                      <input
                        value={timelockPredecessor}
                        onChange={(event) => setTimelockPredecessor(event.target.value)}
                        placeholder={ZERO_HASH}
                      />
                    </label>
                    <label className="field">
                      <span>Salt</span>
                      <input
                        value={timelockSalt}
                        onChange={(event) => setTimelockSalt(event.target.value)}
                        placeholder={ZERO_HASH}
                      />
                    </label>
                  </div>
                </div>
              ) : null}

              <button className="primary-action compact-action" type="button" onClick={handleGenerate}>
                Generate calldata
              </button>
            </div>
          ) : (
            <div className="compact-stack">
              <CodeBlock title="ABI JSON" value={operation.abiJson} onCopy={handleCopy} />

              {isTimelocked ? (
                <div className="decode-switch-row">
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
                  </div>
                </div>
              ) : null}

              {isTimelocked ? (
                <CodeBlock
                  title={`${timelockAction} ABI JSON`}
                  value={timelockAction === "schedule" ? timelockAbis.schedule : timelockAbis.execute}
                  onCopy={handleCopy}
                />
              ) : null}

              <label className="field field-full">
                <span>{operation.mode === "direct" ? "Direct calldata" : "Timelock calldata"}</span>
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
        </section>

        <section className="panel flow-panel">
          <div className="section-heading">
            <h2>4. {interactionMode === "encode" ? "Calldata" : "Decoded result"}</h2>
            <p>
              {interactionMode === "encode"
                ? "Review and copy the generated calldata."
                : "Review decoded fields before signing."}
            </p>
          </div>

          {interactionMode === "encode" ? (
            <div className="result-layout">
              <OutputCard
                title={operation.mode === "direct" ? "Direct calldata" : "Inner calldata"}
                subtitle={
                  operation.mode === "direct"
                    ? "Vault Proxy target"
                    : "Business function calldata for Vault Proxy"
                }
                target={chain.vaultProxy}
                calldata={generatedCalldata}
                onCopy={handleCopy}
              />
              {isTimelocked ? (
                <OutputCard
                  title={`Outer ${timelockAction} calldata`}
                  subtitle={`${timelockLabel} target`}
                  target={timelockTarget}
                  calldata={generatedTimelockCalldata}
                  onCopy={handleCopy}
                />
              ) : null}
            </div>
          ) : (
            <div className="result-layout">
              {operation.mode === "direct" ? (
                <div className="subpanel compact-panel">
                  <div className="section-heading compact">
                    <h3>Decoded parameters</h3>
                  </div>
                  <DecodedRows rows={decodedDirectRows} />
                </div>
              ) : null}
              {isTimelocked ? (
                <div className="subpanel compact-panel">
                  <div className="section-heading compact">
                    <h3>Decoded outer Timelock calldata</h3>
                  </div>
                  <DecodedRows rows={decodedTimelockRows} />
                </div>
              ) : null}
              {isTimelocked ? (
                <div className="subpanel compact-panel">
                  <div className="section-heading compact">
                    <h3>Decoded inner business calldata</h3>
                  </div>
                  <DecodedRows rows={decodedInnerRows} />
                </div>
              ) : null}
            </div>
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

const OutputCard = ({
  title,
  subtitle,
  target,
  calldata,
  onCopy,
}: {
  title: string;
  subtitle: string;
  target: string;
  calldata: string;
  onCopy: (value: string, label: string) => Promise<void>;
}) => (
  <div className="output-card compact-output">
    <div className="output-head">
      <div>
        <h4>{title}</h4>
        <p>{subtitle}</p>
      </div>
    </div>
    <div className="output-meta">
      <span>Target</span>
      <code>{target}</code>
    </div>
    <div className="output-meta">
      <div className="meta-head">
        <span>Calldata</span>
        {calldata ? (
          <button
            type="button"
            className="mini-button icon-button"
            onClick={() => onCopy(calldata, "Calldata copied")}
          >
            <CopyIcon />
            Copy
          </button>
        ) : null}
      </div>
      <pre>{calldata || "Fill the form and generate calldata."}</pre>
    </div>
  </div>
);

const DecodedRows = ({ rows }: { rows: Array<{ label: string; value: string }> }) => {
  if (rows.length === 0) {
    return <p className="empty-state">Decoded parameters will appear here.</p>;
  }
  return (
    <div className="decoded-list">
      {rows.map((row) => (
        <div className="decoded-row" key={row.label}>
          <span>{row.label}</span>
          <pre>{row.value}</pre>
        </div>
      ))}
    </div>
  );
};

export default App;

const CodeBlock = ({
  title,
  value,
  onCopy,
}: {
  title: string;
  value: string;
  onCopy: (value: string, label: string) => Promise<void>;
}) => (
  <div className="code-block">
    <div className="code-head">
      <span>{title}</span>
      <button type="button" className="mini-button icon-button" onClick={() => onCopy(value, `${title} copied`)}>
        <CopyIcon />
        Copy
      </button>
    </div>
    <pre className="abi-box compact-box">{value}</pre>
  </div>
);

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
