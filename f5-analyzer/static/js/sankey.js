/**
 * F5 BIG-IP Analyzer - Sankey Diagram Visualization
 * This file contains all functionality related to rendering and interacting with
 * the Sankey diagram visualization of F5 BIG-IP configurations.
 */

// Global variables
let allVirtualServers = [];
let filteredVirtualServers = [];
let currentPage = 1;
let itemsPerPage = 10; // Show 10 VIPs per page
let sankeyData = null;
let sankeyDiagram = null;

/**
 * Initialize the Sankey diagram visualization
 * @param {Object} data - Analysis results from the server
 */
function initSankeyVisualization(data) {
    // Store all virtual servers
    allVirtualServers = data.virtual_servers || [];
    filteredVirtualServers = [...allVirtualServers];
    
    // Setup pagination
    setupPagination();
    
    // Initial rendering
    updateSankeyVisualization();
    
    // Handle window resize
    window.addEventListener('resize', debounce(() => {
        if (document.getElementById('sankeyView').style.display !== 'none') {
            refreshSankeyDiagram();
        }
    }, 250));
}

/**
 * Update the Sankey visualization with current data and filters
 */
function updateSankeyVisualization() {
    // Get the current page of data
    const startIdx = (currentPage - 1) * itemsPerPage;
    const endIdx = Math.min(startIdx + itemsPerPage, filteredVirtualServers.length);
    const paginatedVIPs = filteredVirtualServers.slice(startIdx, endIdx);
    
    // Prepare data for Sankey diagram
    sankeyData = prepareDataForSankey(paginatedVIPs);
    
    // Render the diagram
    renderSankeyDiagram(sankeyData);
}

/**
 * Refresh the Sankey diagram (used when resizing or switching views)
 */
function refreshSankeyDiagram() {
    if (sankeyData) {
        renderSankeyDiagram(sankeyData);
    }
}

/**
 * Prepare data for the Sankey diagram
 * @param {Array} virtualServers - Virtual servers to include in the diagram
 * @returns {Object} - Data formatted for D3 Sankey
 */
function prepareDataForSankey(virtualServers) {
    const nodes = [];
    const links = [];
    const nodeMap = {};
    let nodeIndex = 0;

    const poolsSet = new Set();
    const nodesSet = new Set();
    const iRulesSet = new Set();

    // Collect unique pools, nodes, iRules
    virtualServers.forEach(vs => {
        if (vs.pool) poolsSet.add(vs.pool);
        if (vs.pool_members) {
            vs.pool_members.forEach(member => nodesSet.add(member.name));
        }
        if (vs.irules) {
            vs.irules.forEach(rule => iRulesSet.add(rule));
        }
    });

    // VIP nodes (column 0)
    virtualServers.forEach(vs => {
        const nodeId = `vip-${vs.name}`;
        nodes.push({
            id: nodeId,
            name: vs.name,
            column: 0,
            type: 'vip',
            details: vs
        });
        nodeMap[nodeId] = nodeIndex++;
    });

    // Pool nodes (column 1)
    Array.from(poolsSet).forEach(poolName => {
        const nodeId = `pool-${poolName}`;
        nodes.push({
            id: nodeId,
            name: poolName,
            column: 1,
            type: 'pool'
        });
        nodeMap[nodeId] = nodeIndex++;
    });

    // Node members (column 2)
    Array.from(nodesSet).forEach(nodeName => {
        const nodeId = `node-${nodeName}`;
        nodes.push({
            id: nodeId,
            name: nodeName,
            column: 2,
            type: 'node'
        });
        nodeMap[nodeId] = nodeIndex++;
    });

    // iRule nodes (column 3)
    Array.from(iRulesSet).forEach(ruleName => {
        const nodeId = `irule-${ruleName}`;
        let iruleDetails = null;
        for (const vs of virtualServers) {
            if (vs.irules_analysis) {
                const match = vs.irules_analysis.find(r => r.name === ruleName || r.fullPath === ruleName);
                if (match) {
                    iruleDetails = match;
                    break;
                }
            }
        }
        nodes.push({
            id: nodeId,
            name: ruleName,
            column: 3,
            type: 'irule',
            details: iruleDetails
        });
        nodeMap[nodeId] = nodeIndex++;
    });

    // Links: VIP → Pool
    virtualServers.forEach(vs => {
        if (vs.pool) {
            const sourceId = `vip-${vs.name}`;
            const targetId = `pool-${vs.pool}`;
            if (nodeMap[sourceId] !== undefined && nodeMap[targetId] !== undefined) {
                links.push({
                    source: sourceId,
                    target: targetId,
                    value: 1,
                    compatibility: determineCompatibility(vs)
                });
            }
        }
    });

    // Links: Pool → Node
    virtualServers.forEach(vs => {
        if (vs.pool && vs.pool_members) {
            const poolId = `pool-${vs.pool}`;
            vs.pool_members.forEach(member => {
                const nodeId = `node-${member.name}`;
                if (nodeMap[poolId] !== undefined && nodeMap[nodeId] !== undefined) {
                    links.push({
                        source: poolId,
                        target: nodeId,
                        value: 1,
                        compatibility: determineCompatibility(vs)
                    });
                }
            });
        }
    });

    // Links: VIP → iRule
    virtualServers.forEach(vs => {
        if (vs.irules) {
            const sourceId = `vip-${vs.name}`;
            vs.irules.forEach(rule => {
                const targetId = `irule-${rule}`;
                if (nodeMap[sourceId] !== undefined && nodeMap[targetId] !== undefined) {
                    let compatibility = determineCompatibility(vs);
                    if (vs.irules_analysis) {
                        const analysis = vs.irules_analysis.find(r => r.name === rule || r.fullPath === rule);
                        if (analysis?.analysis?.unsupported?.length > 0) {
                            compatibility = 'incompatible';
                        } else if (analysis?.analysis?.alternatives?.length > 0) {
                            compatibility = 'warning';
                        }
                    }
                    links.push({
                        source: sourceId,
                        target: targetId,
                        value: 1,
                        compatibility: compatibility
                    });
                }
            });
        }
    });

    // Add default geometry to nodes
    const nodesWithDefaults = nodes.map((node, i) => ({
        ...node,
        index: i,
        x0: 0,
        x1: 0,
        y0: 0,
        y1: 0
    }));

    // Create ID lookup
    const nodeById = Object.fromEntries(nodesWithDefaults.map(n => [n.id, n]));

    // Replace string-based IDs in links with full node objects
    const linksWithReferences = links.map(link => {
        const sourceNode = nodeById[link.source];
        const targetNode = nodeById[link.target];

        if (!sourceNode || !targetNode) {
            console.error('Invalid link (missing node):', link);
            return null;
        }

        console.log('Creating link:', {
            sourceId: link.source,
            targetId: link.target,
            sourceNode: sourceNode.name,
            targetNode: targetNode.name,
            sourcePos: { x0: sourceNode.x0, x1: sourceNode.x1, y0: sourceNode.y0, y1: sourceNode.y1 },
            targetPos: { x0: targetNode.x0, x1: targetNode.x1, y0: targetNode.y0, y1: targetNode.y1 }
        });

        return {
            ...link,
            source: sourceNode,
            target: targetNode
        };
    }).filter(Boolean);

    return {
        nodes: nodesWithDefaults,
        links: linksWithReferences
    };
}


function debugConnectionPoints(svg, data) {
    // Add debug points for each link's source and target
    data.links.forEach(link => {
        // Ensure link.source and link.target are valid objects
        if (!link.source || !link.target) {
            console.error('Invalid link source or target:', link);
            return;
        }
        
        // Source point (right edge of source node)
        const sourceX = link.source.x1 || 0;
        const sourceY = link.source.centerY || (link.source.y0 + (link.source.y1 - link.source.y0) / 2) || 0;
        
        // Target point (left edge of target node)
        const targetX = link.target.x0 || 0;
        const targetY = link.target.centerY || (link.target.y0 + (link.target.y1 - link.target.y0) / 2) || 0;
        
        // Check for NaN values and log them
        if (isNaN(sourceX) || isNaN(sourceY) || isNaN(targetX) || isNaN(targetY)) {
            console.error('NaN coordinates found:', { 
                sourceX, 
                sourceY, 
                targetX, 
                targetY, 
                sourceNode: link.source, 
                targetNode: link.target 
            });
            return; // Skip this link
        }
        
        // Draw source point (red)
        svg.append('circle')
            .attr('cx', sourceX)
            .attr('cy', sourceY)
            .attr('r', 4)
            .attr('fill', 'red');
            
        // Draw target point (green)
        svg.append('circle')
            .attr('cx', targetX)
            .attr('cy', targetY)
            .attr('r', 4)
            .attr('fill', 'green');
            
        // Add debug text for node names - with checks for NaN
        if (!isNaN(sourceY)) {
            svg.append('text')
                .attr('x', sourceX)
                .attr('y', sourceY - 10)
                .attr('fill', 'red')
                .attr('font-size', '10px')
                .text(link.source.name || 'Unknown');
        }
            
        if (!isNaN(targetY)) {
            svg.append('text')
                .attr('x', targetX)
                .attr('y', targetY - 10)
                .attr('fill', 'green')
                .attr('font-size', '10px')
                .text(link.target.name || 'Unknown');
        }
    });
}


/**
 * Determine compatibility status of a component
 * @param {Object} component - Component to check (VIP, iRule, etc.)
 * @returns {string} - 'compatible', 'warning', or 'incompatible'
 */
function determineCompatibility(component) {
    if (!component) return 'compatible';
    
    // Check for incompatibilities
    if (component.f5dc_compatibility && component.f5dc_compatibility.length > 0) {
        return 'incompatible';
    }
    
    // Check for warnings
    if (component.f5dc_warnings && component.f5dc_warnings.length > 0) {
        return 'warning';
    }
    
    // If no issues found, it's compatible
    return 'compatible';
}

/**
 * Render the Sankey diagram with the provided data
 * @param {Object} data - Sankey diagram data (nodes and links)
 */
function renderSankeyDiagram(data) {
    const container = document.getElementById('sankeyContainer');
    if (!container) return;

    container.innerHTML = '';

    const width = container.clientWidth;
    const height = container.clientHeight || 600;

    const svg = d3.select(container)
        .append('svg')
        .attr('width', width)
        .attr('height', height);

    const defs = svg.append('defs');

    // Background gradient
    const bgGradient = defs.append('linearGradient')
        .attr('id', 'bgGradient')
        .attr('x1', '0%').attr('y1', '0%')
        .attr('x2', '100%').attr('y2', '100%');
    bgGradient.append('stop').attr('offset', '0%').attr('stop-color', '#1a1a1a');
    bgGradient.append('stop').attr('offset', '100%').attr('stop-color', '#252525');

    // Define gradients
    defineGradient(defs, 'blueGradient', '#1E88E5', '#64B5F6');
    defineGradient(defs, 'yellowGradient', '#FFC107', '#FFECB3');
    defineGradient(defs, 'redGradient', '#F44336', '#FFCDD2');
    defineGradient(defs, 'vipGradient', '#0d47a1', '#1565c0', 'y');
    defineGradient(defs, 'poolGradient', '#1a237e', '#303f9f', 'y');
    defineGradient(defs, 'nodeGradient', '#4a148c', '#6a1b9a', 'y');
    defineGradient(defs, 'iruleGradient', '#006064', '#00838f', 'y');

    svg.append('rect')
        .attr('width', width)
        .attr('height', height)
        .attr('fill', 'url(#bgGradient)');

    // Padded column layout
    const padding = 100;
    const columnWidth = (width - padding * 2) / 4;
    const columnPositions = [
        padding + columnWidth * 0,
        padding + columnWidth * 1,
        padding + columnWidth * 2,
        padding + columnWidth * 3
    ];

    const columnLabels = ['VIRTUAL SERVERS', 'POOLS', 'NODES', 'iRULES'];
    columnLabels.forEach((label, i) => {
        svg.append('text')
            .attr('x', columnPositions[i])
            .attr('y', 30)
            .attr('text-anchor', 'middle')
            .attr('fill', '#aaa')
            .attr('font-size', '14px')
            .text(label);
    });

    if (!data || !data.nodes || data.nodes.length === 0) {
        svg.append('text')
            .attr('x', width / 2)
            .attr('y', height / 2)
            .attr('text-anchor', 'middle')
            .attr('fill', '#999')
            .attr('font-size', '16px')
            .text('No data available to visualize');
        return;
    }

    // Organize and position nodes
    const nodesByColumn = [[], [], [], []];
    data.nodes.forEach(node => {
        if (typeof node.column === 'number') {
            nodesByColumn[node.column].push(node);
        }
    });

    nodesByColumn.forEach((columnNodes, colIndex) => {
        const columnX = columnPositions[colIndex] || (200 * colIndex + 100);
        const nodeHeight = 40;
        const nodePadding = 10;
        const totalHeight = columnNodes.length * nodeHeight + (columnNodes.length - 1) * nodePadding;
        const startY = (height - totalHeight) / 2;

        columnNodes.forEach((node, i) => {
            node.x0 = Math.max(0, columnX - 75);
            node.x1 = node.x0 + 150;
            node.y0 = startY + i * (nodeHeight + nodePadding);
            node.y1 = node.y0 + nodeHeight;
            node.centerX = (node.x0 + node.x1) / 2;
            node.centerY = (node.y0 + node.y1) / 2;

            console.log(`Positioned ${node.name} [${node.type}] at x0=${node.x0}, x1=${node.x1}, centerY=${node.centerY}`);
        });
    });

    // Draw links
    const linkGroup = svg.append('g').attr('class', 'links');
    data.links.forEach(link => {
        const s = link.source;
        const t = link.target;
        if (!s || !t) return;

        const sourceX = s.x1;
        const sourceY = s.centerY;
        const targetX = t.x0;
        const targetY = t.centerY;

        if ([sourceX, sourceY, targetX, targetY].some(isNaN)) {
            console.warn('Skipping link due to NaN:', link);
            return;
        }

        let linkColor = 'url(#blueGradient)';
        if (link.compatibility === 'warning') linkColor = 'url(#yellowGradient)';
        else if (link.compatibility === 'incompatible') linkColor = 'url(#redGradient)';
        const yOffset = Math.abs(targetY - sourceY) < 2 ? 20 : 0;
        linkGroup.append('path')

            .attr('d', `M ${sourceX},${sourceY} C ${sourceX + 50},${sourceY + yOffset} ${targetX - 50},${targetY - yOffset} ${targetX},${targetY}`)
            .attr('stroke', linkColor)
            .attr('stroke-width', 15)
            .attr('fill', 'none')
            .attr('opacity', 0.9)
            .attr('cursor', 'pointer')
            .on('mouseover', function () {
                d3.select(this).attr('stroke-width', 20).attr('opacity', 1.0);
            })
            .on('mouseout', function () {
                d3.select(this).attr('stroke-width', 15).attr('opacity', 0.9);
            });

        console.log(`Drawing link from ${s.name} to ${t.name} at (${sourceX},${sourceY}) → (${targetX},${targetY})`);
    });

    // Draw nodes
    const nodeGroup = svg.append('g').attr('class', 'nodes');
    data.nodes.forEach(node => {
        let gradient;
        switch (node.type) {
            case 'vip': gradient = 'url(#vipGradient)'; break;
            case 'pool': gradient = 'url(#poolGradient)'; break;
            case 'node': gradient = 'url(#nodeGradient)'; break;
            case 'irule': gradient = 'url(#iruleGradient)'; break;
            default: gradient = '#555';
        }

        const group = nodeGroup.append('g')
            .attr('transform', `translate(${node.x0},${node.y0})`)
            .attr('cursor', 'pointer')
            .on('click', () => showComponentDetails(node));

        group.append('rect')
            .attr('width', node.x1 - node.x0)
            .attr('height', node.y1 - node.y0)
            .attr('fill', gradient)
            .attr('rx', 4)
            .attr('ry', 4)
            .attr('stroke', '#444')
            .attr('stroke-width', 1);

        group.append('text')
            .attr('x', (node.x1 - node.x0) / 2)
            .attr('y', (node.y1 - node.y0) / 2)
            .attr('dy', '0.35em')
            .attr('text-anchor', 'middle')
            .attr('fill', 'white')
            .attr('font-size', '13px')
            .text(node.name);

        if (node.type === 'vip' && node.details?.destination) {
            group.append('text')
                .attr('x', (node.x1 - node.x0) / 2)
                .attr('y', (node.y1 - node.y0) / 2 + 15)
                .attr('dy', '0.35em')
                .attr('text-anchor', 'middle')
                .attr('fill', '#bbb')
                .attr('font-size', '11px')
                .text(node.details.destination);
        }
    });
}



/**
 * Define a gradient in the SVG defs section
 * @param {Object} defs - The SVG defs element
 * @param {string} id - ID for the gradient
 * @param {string} color1 - Start color
 * @param {string} color2 - End color
 * @param {string} direction - 'x' for horizontal, 'y' for vertical
 */
function defineGradient(defs, id, color1, color2, direction = 'x') {
    const gradient = defs.append('linearGradient')
        .attr('id', id);
    
    if (direction === 'x') {
        gradient.attr('x1', '0%').attr('y1', '0%')
               .attr('x2', '100%').attr('y2', '0%');
    } else {
        gradient.attr('x1', '0%').attr('y1', '0%')
               .attr('x2', '0%').attr('y2', '100%');
    }
    
    gradient.append('stop')
        .attr('offset', '0%')
        .attr('stop-color', color1)
        .attr('stop-opacity', 1.0); // Full opacity

    gradient.append('stop')
        .attr('offset', '100%')
        .attr('stop-color', color2)
        .attr('stop-opacity', 1.0); // Full opacity
}

/**
 * Show component details in the details panel
 * @param {Object} component - The node to show details for
 */
function showComponentDetails(component) {
    const detailsPanel = document.getElementById('detailsPanel');
    if (!detailsPanel) return;
    
    let html = '';
    let details = component.details;
    
    switch(component.type) {
        case 'vip':
            html = createVipDetailsHTML(details);
            break;
        case 'pool':
            html = createPoolDetailsHTML(component.name);
            break;
        case 'node':
            html = createNodeDetailsHTML(component.name);
            break;
        case 'irule':
            html = createIRuleDetailsHTML(details, component.name);
            break;
        default:
            html = `<div class="placeholder-panel">
                        <h3>No details available</h3>
                        <p>No detailed information is available for this component.</p>
                    </div>`;
    }
    
    detailsPanel.innerHTML = html;
}

/**
 * Create HTML for VIP details
 * @param {Object} vip - Virtual server details
 * @returns {string} - HTML for details panel
 */
function createVipDetailsHTML(vip) {
    if (!vip) return '';
    
    let html = `
        <h3>${vip.name} (Virtual Server)</h3>
        <div style="display: flex; justify-content: space-between; margin-bottom: 15px;">
            <div><strong>Destination:</strong> ${vip.destination}</div>
            <div><strong>Pool:</strong> ${vip.pool || 'None'}</div>
        </div>
    `;
    
    // Pool Members
    if (vip.pool_members && vip.pool_members.length > 0) {
        html += '<div style="margin-bottom: 15px;"><strong>Pool Members:</strong>';
        html += '<table><tr><th>Name</th><th>Address</th></tr>';
        vip.pool_members.forEach(member => {
            html += `<tr><td>${member.name}</td><td>${member.address}</td></tr>`;
        });
        html += '</table></div>';
    }
    
    // iRules
    if (vip.irules && vip.irules.length > 0) {
        html += '<div style="margin-bottom: 15px;"><strong>iRules:</strong><ul>';
        vip.irules.forEach(rule => {
            html += `<li>${rule}</li>`;
        });
        html += '</ul></div>';
    }
    
    // Compatibility issues
    if (vip.f5dc_compatibility && vip.f5dc_compatibility.length > 0) {
        html += `
            <div class="compatibility-section incompatible">
                <strong>F5 Distributed Cloud Compatibility Issues:</strong>
                <ul class="issue-list">
                    ${vip.f5dc_compatibility.map(item => `<li>${item}</li>`).join('')}
                </ul>
            </div>
        `;
    } else if (vip.f5dc_warnings && vip.f5dc_warnings.length > 0) {
        html += `
            <div class="compatibility-section warning-section">
                <strong>F5 Distributed Cloud Warnings:</strong>
                <ul class="issue-list">
                    ${vip.f5dc_warnings.map(item => `<li>${item}</li>`).join('')}
                </ul>
            </div>
        `;
    } else {
        html += `
            <div class="compatibility-section compatible">
                <strong>F5 Distributed Cloud Compatibility:</strong> ✓ Fully compatible
            </div>
        `;
    }
    
    return html;
}

/**
 * Create HTML for Pool details
 * @param {string} poolName - Pool name
 * @returns {string} - HTML for details panel
 */
function createPoolDetailsHTML(poolName) {
    // Try to find the pool in any of the virtual servers
    let poolInfo = null;
    let poolMembers = [];
    
    for (const vs of filteredVirtualServers) {
        if (vs.pool === poolName) {
            poolInfo = {
                name: poolName,
                virtual_server: vs.name,
                destination: vs.destination
            };
            poolMembers = vs.pool_members || [];
            break;
        }
    }
    
    if (!poolInfo) {
        return `
            <div class="placeholder-panel">
                <h3>${poolName} (Pool)</h3>
                <p>No detailed information is available for this pool.</p>
            </div>
        `;
    }
    
    let html = `
        <h3>${poolInfo.name} (Pool)</h3>
        <div style="margin-bottom: 15px;">
            <div><strong>Used by Virtual Server:</strong> ${poolInfo.virtual_server}</div>
        </div>
    `;
    
    // Pool Members
    if (poolMembers.length > 0) {
        html += '<div style="margin-bottom: 15px;"><strong>Pool Members:</strong>';
        html += '<table><tr><th>Name</th><th>Address</th></tr>';
        poolMembers.forEach(member => {
            html += `<tr><td>${member.name}</td><td>${member.address}</td></tr>`;
        });
        html += '</table></div>';
    } else {
        html += '<div style="margin-bottom: 15px;"><strong>Pool Members:</strong> No members found</div>';
    }
    
    return html;
}

/**
 * Create HTML for Node details
 * @param {string} nodeName - Node name
 * @returns {string} - HTML for details panel
 */
function createNodeDetailsHTML(nodeName) {
    // Try to find the node in any of the virtual servers
    let nodeInfo = null;
    
    for (const vs of filteredVirtualServers) {
        if (vs.pool_members) {
            const member = vs.pool_members.find(m => m.name === nodeName);
            if (member) {
                nodeInfo = {
                    name: nodeName,
                    address: member.address,
                    pool: vs.pool,
                    virtual_server: vs.name
                };
                break;
            }
        }
    }
    
    if (!nodeInfo) {
        return `
            <div class="placeholder-panel">
                <h3>${nodeName} (Node)</h3>
                <p>No detailed information is available for this node.</p>
            </div>
        `;
    }
    
    let html = `
        <h3>${nodeInfo.name} (Node)</h3>
        <div style="margin-bottom: 15px;">
            <div><strong>Address:</strong> ${nodeInfo.address || 'Unknown'}</div>
            <div><strong>Pool:</strong> ${nodeInfo.pool || 'Unknown'}</div>
            <div><strong>Used by Virtual Server:</strong> ${nodeInfo.virtual_server || 'Unknown'}</div>
        </div>
    `;
    
    return html;
}

/**
 * Create HTML for iRule details
 * @param {Object} irule - iRule details
 * @param {string} ruleName - iRule name
 * @returns {string} - HTML for details panel
 */
function createIRuleDetailsHTML(irule, ruleName) {
    if (!irule) {
        // Try to find the iRule in any of the virtual servers
        for (const vs of filteredVirtualServers) {
            if (vs.irules_analysis) {
                const ruleAnalysis = vs.irules_analysis.find(r => r.name === ruleName || r.fullPath === ruleName);
                if (ruleAnalysis) {
                    irule = ruleAnalysis;
                    break;
                }
            }
        }
    }
    
    if (!irule) {
        return `
            <div class="placeholder-panel">
                <h3>${ruleName} (iRule)</h3>
                <p>No detailed information is available for this iRule.</p>
            </div>
        `;
    }
    
    // Determine compatibility status
    let compatibilityStatus = 'compatible';
    let compatibilityText = '✓ Fully compatible';
    
    const analysis = irule.analysis || {};
    
    if (analysis.unsupported && analysis.unsupported.length > 0) {
        compatibilityStatus = 'incompatible';
        compatibilityText = '✗ Incompatible';
    } else if (analysis.alternatives && analysis.alternatives.length > 0) {
        compatibilityStatus = 'warning';
        compatibilityText = '⚠️ Requires Changes';
    }
    
    // Determine events
    let eventsText = 'None';
    if (analysis.events && Object.keys(analysis.events).length > 0) {
        eventsText = Object.keys(analysis.events).join(', ');
    }
    
    let html = `
        <h3>${irule.name} (iRule)</h3>
        <div style="display: flex; justify-content: space-between; margin-bottom: 15px;">
            <div><strong>Compatibility:</strong> <span class="${compatibilityStatus}">${compatibilityText}</span></div>
            <div><strong>Events:</strong> ${eventsText}</div>
        </div>
    `;
    
    // Add iRule content if available
    if (irule.content || irule.tcl_content) {
        const iruleContent = irule.content || irule.tcl_content;
        html += `
            <div style="margin-bottom: 20px;">
                <div class="code-block">
                    ${formatIRuleCode(iruleContent)}
                </div>
            </div>
        `;
    }
    
    // Add compatibility analysis
    if (analysis) {
        // Add mappable features
        if (analysis.mappable && analysis.mappable.length > 0) {
            html += `<div class="compatibility-section mappable-section">
                <strong>Mappable to F5 Distributed Cloud:</strong>
                <ul>`;
            analysis.mappable.forEach(item => {
                html += `<li>${item.feature}`;
                if (item.service_policy) {
                    html += ` - ${item.service_policy}`;
                }
                if (item.event) {
                    html += ` (${item.event})`;
                }
                html += `</li>`;
            });
            html += `</ul></div>`;
        }
        
        // Add features requiring alternatives
        if (analysis.alternatives && analysis.alternatives.length > 0) {
            html += `<div class="compatibility-section alternatives-section">
                <strong>Requires Alternatives in F5 Distributed Cloud:</strong>
                <ul>`;
            analysis.alternatives.forEach(item => {
                html += `<li>${item.feature}`;
                if (item.alternative) {
                    html += ` - ${item.alternative}`;
                }
                if (item.event) {
                    html += ` (${item.event})`;
                }
                html += `</li>`;
            });
            html += `</ul></div>`;
        }
        
        // Add unsupported features
        if (analysis.unsupported && analysis.unsupported.length > 0) {
            html += `<div class="compatibility-section unsupported-section">
                <strong>Not Supported in F5 Distributed Cloud:</strong>
                <ul>`;
            analysis.unsupported.forEach(item => {
                html += `<li>${item.feature}`;
                if (item.note) {
                    html += ` - ${item.note}`;
                }
                if (item.event) {
                    html += ` (${item.event})`;
                }
                html += `</li>`;
            });
            html += `</ul></div>`;
        }
        
        // Add warnings
        if (analysis.warnings && analysis.warnings.length > 0) {
            html += `<div class="compatibility-section warning-section">
                <strong>Migration Considerations:</strong>
                <ul>`;
            analysis.warnings.forEach(item => {
                html += `<li>${item.feature}`;
                if (item.note) {
                    html += ` - ${item.note}`;
                }
                if (item.event) {
                    html += ` (${item.event})`;
                }
                html += `</li>`;
            });
            html += `</ul></div>`;
        }
    }
    
    return html;
}

/**
 * Format iRule code with syntax highlighting
 * @param {string} code - iRule code to format
 * @returns {string} - HTML with syntax highlighting
 */
function formatIRuleCode(code) {
    if (!code) return '';
    
    // Simple syntax highlighting for TCL/iRule
    return code
        .replace(/\b(when|if|else|foreach|set|switch|case|default|proc)\b/g, '<span class="code-keyword">$1</span>')
        .replace(/"([^"]*)"/g, '<span class="code-string">"$1"</span>')
        .replace(/\b(HTTP::uri|HTTP::header|string|map|exists|remove|insert|class|pool|node|virtual|clientside|serverside)\b/g, '<span class="code-function">$1</span>')
        .replace(/#.*/g, '<span class="code-comment">$&</span>');
}

/**
 * Set up pagination controls
 */
function setupPagination() {
    updatePaginationControls();
    
    // Add event listener for window resize to update pagination if needed
    window.addEventListener('resize', debounce(() => {
        if (document.getElementById('sankeyView').style.display !== 'none') {
            updatePaginationControls();
        }
    }, 250));
}

/**
 * Update pagination controls based on current data
 */
function updatePaginationControls() {
    const paginationControls = document.getElementById('paginationControls');
    if (!paginationControls) return;
    
    const totalPages = Math.ceil(filteredVirtualServers.length / itemsPerPage);
    
    let paginationHTML = '';
    
    // Previous button
    paginationHTML += `<button ${currentPage === 1 ? 'disabled' : ''} data-page="prev">« Prev</button>`;
    
    // Page buttons
    for (let i = 1; i <= totalPages; i++) {
        paginationHTML += `<button ${i === currentPage ? 'class="active"' : ''} data-page="${i}">${i}</button>`;
    }
    
    // Next button
    paginationHTML += `<button ${currentPage === totalPages ? 'disabled' : ''} data-page="next">Next »</button>`;
    
    paginationControls.innerHTML = paginationHTML;
    
    // Add event listeners to pagination buttons
    const buttons = paginationControls.querySelectorAll('button');
    buttons.forEach(button => {
        button.addEventListener('click', function() {
            const page = this.getAttribute('data-page');
            
            if (page === 'prev' && currentPage > 1) {
                currentPage--;
            } else if (page === 'next' && currentPage < totalPages) {
                currentPage++;
            } else if (page !== 'prev' && page !== 'next') {
                currentPage = parseInt(page);
            }
            
            updatePaginationControls();
            updateSankeyVisualization();
        });
    });
}

/**
 * Filter the Sankey data based on selected filters
 * @param {string} filterType - Type of filter to apply
 * @param {string} searchText - Text to search for
 */
function filterSankeyData(filterType, searchText) {
    // Start with all virtual servers
    filteredVirtualServers = [...allVirtualServers];
    
    // Apply filter by type
    switch (filterType) {
        case 'http':
            // Filter for HTTP virtual servers (typically port 80, 443, 8080, 8443)
            filteredVirtualServers = filteredVirtualServers.filter(vs => {
                const destination = vs.destination || '';
                return destination.includes(':80') || 
                       destination.includes(':443') || 
                       destination.includes(':8080') || 
                       destination.includes(':8443');
            });
            break;
        case 'tcp':
            // Filter for non-HTTP virtual servers
            filteredVirtualServers = filteredVirtualServers.filter(vs => {
                const destination = vs.destination || '';
                return !destination.includes(':80') && 
                       !destination.includes(':443') && 
                       !destination.includes(':8080') && 
                       !destination.includes(':8443');
            });
            break;
        case 'issues':
            // Filter for virtual servers with compatibility issues
            filteredVirtualServers = filteredVirtualServers.filter(vs => {
                return (vs.f5dc_compatibility && vs.f5dc_compatibility.length > 0) || 
                       (vs.f5dc_warnings && vs.f5dc_warnings.length > 0) ||
                       (vs.nginx_compatibility && vs.nginx_compatibility.length > 0);
            });
            break;
    }
    
    // Apply search filter if text is provided
    if (searchText) {
        filteredVirtualServers = filteredVirtualServers.filter(vs => {
            return (vs.name && vs.name.toLowerCase().includes(searchText)) || 
                   (vs.destination && vs.destination.toLowerCase().includes(searchText)) ||
                   (vs.pool && vs.pool.toLowerCase().includes(searchText));
        });
    }
    
    // Reset to first page
    currentPage = 1;
    
    // Update pagination and visualization
    updatePaginationControls();
    updateSankeyVisualization();
}

/**
 * Debounce function to limit how often a function can be called
 * @param {Function} func - Function to debounce
 * @param {number} wait - Time to wait in milliseconds
 * @returns {Function} - Debounced function
 */
function debounce(func, wait) {
    let timeout;
    return function(...args) {
        const context = this;
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(context, args), wait);
    };
}
