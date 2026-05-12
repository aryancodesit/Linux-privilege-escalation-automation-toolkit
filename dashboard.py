import streamlit as st
import json
import os
import glob
import pandas as pd
import plotly.express as px

st.set_page_config(page_title="Linux PrivEsc Toolkit Dashboard", page_icon="🛡️", layout="wide")

def load_reports(reports_dir="reports"):
    reports = {}
    if not os.path.exists(reports_dir):
        return reports
    
    for file_path in glob.glob(os.path.join(reports_dir, "*.json")):
        with open(file_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                # Use filename as fallback if scan_name isn't unique
                name = os.path.basename(file_path)
                reports[name] = data
            except json.JSONDecodeError:
                continue
    return reports

def main():
    st.title("🛡️ Linux Privilege Escalation Automation Toolkit")
    st.markdown("### Executive Dashboard")
    
    reports = load_reports()
    
    if not reports:
        st.warning("No scan reports found in the 'reports' directory. Please run the scanner first.")
        return
    
    # Sidebar for report selection
    st.sidebar.header("Select Scan Report")
    selected_report_name = st.sidebar.selectbox("Reports", list(reports.keys()))
    
    report_data = reports[selected_report_name]
    
    # System Information
    st.header("💻 System Information")
    sys_info = report_data.get("system_info", {})
    
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Hostname", sys_info.get("hostname", "Unknown"))
    col2.metric("OS Release", sys_info.get("os_pretty_name", "Unknown"))
    col3.metric("Kernel", sys_info.get("kernel_release", "Unknown"))
    col4.metric("Scanned By User", sys_info.get("username", "Unknown"))
    
    st.caption(f"Scan generated at: {report_data.get('generated_at_utc', 'Unknown')}")
    st.markdown("---")
    
    findings = report_data.get("findings", [])
    if not findings:
        st.success("No vulnerabilities found! 🎉")
        return
        
    df = pd.DataFrame(findings)
    
    # Metrics
    st.header("📊 Threat Overview")
    
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    df['severity_score'] = df['severity'].str.lower().map(severity_order).fillna(0)
    
    sev_counts = df['severity'].str.lower().value_counts()
    
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("🔴 Critical", sev_counts.get("critical", 0))
    m2.metric("🟠 High", sev_counts.get("high", 0))
    m3.metric("🟡 Medium", sev_counts.get("medium", 0))
    m4.metric("🔵 Low/Info", sev_counts.get("low", 0) + sev_counts.get("info", 0))
    
    # Charts
    col_chart1, col_chart2 = st.columns(2)
    
    with col_chart1:
        st.subheader("Findings by Severity")
        fig_sev = px.pie(names=sev_counts.index, values=sev_counts.values, 
                         color=sev_counts.index,
                         color_discrete_map={
                             "critical": "#ef4444",
                             "high": "#f97316",
                             "medium": "#eab308",
                             "low": "#3b82f6",
                             "info": "#94a3b8"
                         })
        st.plotly_chart(fig_sev, use_container_width=True)
        
    with col_chart2:
        st.subheader("Findings by Module")
        mod_counts = df['module'].value_counts().reset_index()
        mod_counts.columns = ['module', 'count']
        fig_mod = px.bar(mod_counts, x='module', y='count', color='module')
        st.plotly_chart(fig_mod, use_container_width=True)

    st.markdown("---")
    st.header("📝 Detailed Findings")
    
    # Filters
    f_col1, f_col2 = st.columns(2)
    with f_col1:
        sel_severity = st.multiselect("Filter by Severity", options=df['severity'].unique(), default=df['severity'].unique())
    with f_col2:
        sel_module = st.multiselect("Filter by Module", options=df['module'].unique(), default=df['module'].unique())
        
    filtered_df = df[df['severity'].isin(sel_severity) & df['module'].isin(sel_module)]
    filtered_df = filtered_df.sort_values(by="severity_score", ascending=False)
    
    # Display table (hide score and some long text fields for compactness, expander for details)
    display_df = filtered_df[['severity', 'module', 'title', 'affected_path_or_command']].copy()
    display_df['severity'] = display_df['severity'].str.upper()
    
    st.dataframe(display_df, use_container_width=True, hide_index=True)
    
    st.subheader("Deep Dive Analysis")
    for _, row in filtered_df.iterrows():
        with st.expander(f"[{row['severity'].upper()}] {row['module'].upper()}: {row['title']} - {row['affected_path_or_command']}"):
            st.markdown(f"**Evidence:**\n```\n{row.get('evidence', 'N/A')}\n```")
            st.markdown(f"**Exploitation Possibility:**\n{row.get('exploitation_possibility', 'N/A')}")
            st.markdown(f"**Mitigation:**\n{row.get('mitigation', 'N/A')}")

if __name__ == "__main__":
    main()
