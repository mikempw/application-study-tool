CREATE DATABASE IF NOT EXISTS f5_analyzer;

-- Table for storing analysis sessions
CREATE TABLE IF NOT EXISTS f5_analyzer.analysis_sessions (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),
    hostname String,
    username String,
    summary_virtual_servers UInt32,
    summary_pools UInt32,
    summary_irules UInt32,
    summary_asm_policies UInt32,
    summary_apm_policies UInt32,
    PRIMARY KEY (id)
) ENGINE = MergeTree();

-- Table for storing virtual server analysis
CREATE TABLE IF NOT EXISTS f5_analyzer.virtual_servers (
    id UUID DEFAULT generateUUIDv4(),
    session_id UUID,
    timestamp DateTime DEFAULT now(),
    name String,
    partition String,
    full_path String,
    destination String,
    pool String,
    has_compatibility_issues UInt8,
    nginx_compatibility_issues Array(String),
    f5dc_compatibility_issues Array(String),
    f5dc_warnings Array(String),
    PRIMARY KEY (id)
) ENGINE = MergeTree();

-- Table for storing iRule analysis
CREATE TABLE IF NOT EXISTS f5_analyzer.irule_analysis (
    id UUID DEFAULT generateUUIDv4(),
    session_id UUID,
    virtual_server_id UUID,
    timestamp DateTime DEFAULT now(),
    name String,
    partition String,
    full_path String,
    mappable_features Array(String),
    alternative_features Array(String),
    unsupported_features Array(String),
    warnings Array(String),
    events Array(String),
    PRIMARY KEY (id)
) ENGINE = MergeTree();

-- Create a view that joins the data
CREATE VIEW IF NOT EXISTS f5_analyzer.analysis_report AS
SELECT 
    a.id as session_id,
    a.timestamp as analysis_time,
    a.hostname,
    a.summary_virtual_servers,
    a.summary_irules,
    vs.name as virtual_server,
    vs.full_path as virtual_server_path,
    vs.has_compatibility_issues,
    ir.name as irule_name,
    ir.full_path as irule_path,
    ir.mappable_features,
    ir.alternative_features,
    ir.unsupported_features,
    ir.warnings as irule_warnings
FROM f5_analyzer.analysis_sessions a
LEFT JOIN f5_analyzer.virtual_servers vs ON a.id = vs.session_id
LEFT JOIN f5_analyzer.irule_analysis ir ON vs.id = ir.virtual_server_id;
