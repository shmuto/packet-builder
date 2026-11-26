import { useMemo, useState } from 'react';
import type { ByteRange, DissectionNode } from '../../core/bgp';

export interface BgpMessageInspectorProps {
  readonly title: string;
  readonly subtitle?: string;
  readonly bgpBytes?: Uint8Array;
  readonly tree?: DissectionNode;
  readonly explanations?: readonly string[];
  readonly tcpOnlyNote?: string;
}

function findDeepestNodeAtByte(node: DissectionNode, byteIndex: number): DissectionNode | null {
  if (byteIndex < node.byteRange.start || byteIndex >= node.byteRange.end) {
    return null;
  }
  if (node.children) {
    for (const child of node.children) {
      const hit = findDeepestNodeAtByte(child, byteIndex);
      if (hit) return hit;
    }
  }
  return node;
}

function formatAsciiChar(byte: number): string {
  return byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : '.';
}

interface TreeNodeRowProps {
  readonly node: DissectionNode;
  readonly depth: number;
  readonly highlightedId: string | null;
  readonly selectedRange: ByteRange | null;
  readonly onHoverNode: (node: DissectionNode | null) => void;
  readonly onSelectNode: (node: DissectionNode) => void;
}

function TreeNodeRow({
  node,
  depth,
  highlightedId,
  selectedRange,
  onHoverNode,
  onSelectNode,
}: TreeNodeRowProps) {
  const hasChildren = Boolean(node.children && node.children.length > 0);
  // Expand root and top two levels by default so key fields (My AS, Capabilities, Path Attributes, NLRI) are immediately visible
  const [expanded, setExpanded] = useState(depth < 2);

  const isHighlighted =
    highlightedId === node.id ||
    (selectedRange !== null &&
      selectedRange.start === node.byteRange.start &&
      selectedRange.end === node.byteRange.end &&
      !hasChildren);

  const byteCount = node.byteRange.end - node.byteRange.start;

  return (
    <div className="bgp-tree-item" role="treeitem" aria-expanded={hasChildren ? expanded : undefined}>
      <div
        className={`bgp-tree-row${isHighlighted ? ' is-highlighted' : ''}`}
        style={{ paddingLeft: `${depth * 16 + 8}px` }}
        onMouseEnter={() => onHoverNode(node)}
        onMouseLeave={() => onHoverNode(null)}
        onClick={() => onSelectNode(node)}
      >
        {hasChildren ? (
          <button
            type="button"
            className="bgp-tree-toggle"
            aria-label={`${expanded ? 'Collapse' : 'Expand'} ${node.label}`}
            onClick={(e) => {
              e.stopPropagation();
              setExpanded((prev) => !prev);
            }}
          >
            {expanded ? '▾' : '▸'}
          </button>
        ) : (
          <span className="bgp-tree-leaf-dot" aria-hidden="true">
            ·
          </span>
        )}
        <div className="bgp-tree-content">
          <div className="bgp-tree-headline">
            <span className="bgp-tree-label">{node.label}</span>
            <span className="bgp-tree-value mono">{node.value}</span>
            <span className="bgp-tree-ref mono">{node.reference}</span>
            <span className="bgp-tree-range mono">
              {byteCount === 1
                ? `B${node.byteRange.start}`
                : `B${node.byteRange.start}–${node.byteRange.end - 1}`}
            </span>
          </div>
          <p className="bgp-tree-explanation">{node.explanation}</p>
        </div>
      </div>

      {hasChildren && expanded && (
        <div className="bgp-tree-children" role="group">
          {node.children!.map((child) => (
            <TreeNodeRow
              key={child.id}
              node={child}
              depth={depth + 1}
              highlightedId={highlightedId}
              selectedRange={selectedRange}
              onHoverNode={onHoverNode}
              onSelectNode={onSelectNode}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export function BgpMessageInspector({
  title,
  subtitle,
  bgpBytes,
  tree,
  explanations = [],
  tcpOnlyNote,
}: BgpMessageInspectorProps) {
  const [hoveredNode, setHoveredNode] = useState<DissectionNode | null>(null);
  const [pinnedNode, setPinnedNode] = useState<DissectionNode | null>(null);
  const [hoveredByte, setHoveredByte] = useState<number | null>(null);

  const byteMatchedNode = useMemo(() => {
    if (hoveredByte === null || !tree) return null;
    return findDeepestNodeAtByte(tree, hoveredByte);
  }, [hoveredByte, tree]);

  const activeNode = hoveredNode ?? byteMatchedNode ?? pinnedNode;
  const activeRange = activeNode?.byteRange ?? null;

  const hexRows = useMemo(() => {
    if (!bgpBytes || bgpBytes.length === 0) return [];
    const rows: { offset: number; bytes: number[] }[] = [];
    for (let offset = 0; offset < bgpBytes.length; offset += 16) {
      rows.push({
        offset,
        bytes: Array.from(bgpBytes.subarray(offset, Math.min(offset + 16, bgpBytes.length))),
      });
    }
    return rows;
  }, [bgpBytes]);

  return (
    <section className="bgp-panel bgp-inspector" aria-label="Message Inspector">
      <div className="bgp-panel-header">
        <div>
          <h2 className="bgp-panel-title">{title}</h2>
          {subtitle && <p className="bgp-panel-subtitle mono">{subtitle}</p>}
        </div>
        {bgpBytes && (
          <span className="bgp-size-pill mono">{bgpBytes.length} bytes</span>
        )}
      </div>

      {explanations.length > 0 && (
        <div className="bgp-why-box" aria-label="Why does it look like this?">
          <h3 className="bgp-why-title">Why does it look like this?</h3>
          <ul className="bgp-why-list">
            {explanations.map((line, idx) => (
              <li key={idx}>{line}</li>
            ))}
          </ul>
        </div>
      )}

      {tcpOnlyNote && <p className="bgp-tcp-note">{tcpOnlyNote}</p>}

      {tree && (
        <div className="bgp-tree" role="tree" aria-label="BGP Message Dissection Tree">
          <TreeNodeRow
            node={tree}
            depth={0}
            highlightedId={activeNode?.id ?? null}
            selectedRange={activeRange}
            onHoverNode={setHoveredNode}
            onSelectNode={(n) => setPinnedNode((prev) => (prev?.id === n.id ? null : n))}
          />
        </div>
      )}

      {bgpBytes && bgpBytes.length > 0 && (
        <details className="bgp-bytes-details">
          <summary className="bgp-bytes-summary">
            Bytes ({bgpBytes.length} octets — hover bytes or tree fields to cross-highlight)
          </summary>

          {activeNode && (
            <div className="bgp-byte-strip">
              <span className="bgp-byte-strip-label">{activeNode.label}:</span>{' '}
              <span className="mono">{activeNode.value}</span>{' '}
              <span className="bgp-tree-ref mono">{activeNode.reference}</span>
            </div>
          )}

          <div className="bgp-hexdump mono" onMouseLeave={() => setHoveredByte(null)}>
            {hexRows.map((row) => (
              <div key={row.offset} className="bgp-hexdump-row">
                <span className="bgp-hexdump-offset">
                  {row.offset.toString(16).padStart(4, '0')}:
                </span>
                <span className="bgp-hexdump-bytes">
                  {row.bytes.map((b, idx) => {
                    const byteIdx = row.offset + idx;
                    const isHit =
                      activeRange !== null &&
                      byteIdx >= activeRange.start &&
                      byteIdx < activeRange.end;
                    return (
                      <span
                        key={byteIdx}
                        className={`bgp-hex-byte${idx === 7 ? ' is-mid-gap' : ''}${isHit ? ' is-highlighted' : ''}`}
                        onMouseEnter={() => setHoveredByte(byteIdx)}
                      >
                        {b.toString(16).padStart(2, '0')}
                      </span>
                    );
                  })}
                </span>
                <span className="bgp-hexdump-ascii">
                  {row.bytes.map((b, idx) => {
                    const byteIdx = row.offset + idx;
                    const isHit =
                      activeRange !== null &&
                      byteIdx >= activeRange.start &&
                      byteIdx < activeRange.end;
                    return (
                      <span
                        key={byteIdx}
                        className={`bgp-ascii-char${isHit ? ' is-highlighted' : ''}`}
                        onMouseEnter={() => setHoveredByte(byteIdx)}
                      >
                        {formatAsciiChar(b)}
                      </span>
                    );
                  })}
                </span>
              </div>
            ))}
          </div>
        </details>
      )}
    </section>
  );
}
