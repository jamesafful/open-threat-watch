import dash
import dash_table
from dash import html, dcc, Input, Output, State
import dash_table
import pandas as pd
import sqlite3
import joblib

# Load model + vectorizer
model = joblib.load("ml/severity_model.pkl")
vectorizer = joblib.load("ml/tfidf_vectorizer.pkl")

# Load DB
def get_cve_data():
    conn = sqlite3.connect("data/cves.db")
    df = pd.read_sql_query("SELECT * FROM cves", conn)
    conn.close()
    return df

df = get_cve_data()

# Build Dash app
app = dash.Dash(__name__)
app.title = "OpenThreatWatch Dashboard"

app.layout = html.Div([
    html.H1("🔐 OpenThreatWatch – CVE Dashboard", style={
        "textAlign": "center",
        "fontSize": "2.5rem",
        "marginBottom": "2rem"
    }),

    html.Div([
        dcc.Input(
            id="keyword", type="text", placeholder="Search CVEs...",
            style={"width": "70%", "padding": "0.5rem", "marginRight": "0.5rem"}
        ),
        html.Button("Search", id="search-btn", style={
            "padding": "0.5rem 1rem", "background": "#007BFF",
            "color": "white", "border": "none", "borderRadius": "4px"
        }),
    ], style={"textAlign": "center", "marginBottom": "2rem"}),

    html.Div([
        html.Div([
            html.H3("📊 CVE Severity Breakdown"),
            dcc.Graph(id="severity-chart", style={"height": "300px"})
        ], style={"width": "48%"}),

        html.Div([
            html.H3("📈 CVE Publication Timeline"),
            dcc.Graph(id="timeline-chart", style={"height": "300px"})
        ], style={"width": "48%"})
    ], style={"display": "flex", "justifyContent": "space-between", "marginBottom": "2rem"}),

    html.Hr(),

    html.Div([
        html.H3("🧠 Predict Severity of New Description"),
        dcc.Textarea(id="desc-input", style={"width": "100%", "padding": "0.5rem"}, rows=4),
        html.Button("Predict", id="predict-btn", style={
            "marginTop": "0.5rem", "padding": "0.5rem 1rem",
            "background": "#28a745", "color": "white",
            "border": "none", "borderRadius": "4px"
        }),
        html.Div(id="prediction-output", style={
            "marginTop": "1rem", "fontWeight": "bold", "fontSize": "1.2rem"
        })
    ], style={
        "background": "#f9f9f9", "padding": "1rem",
        "borderRadius": "8px", "boxShadow": "0 0 8px rgba(0,0,0,0.05)",
        "marginBottom": "2rem"
    }),

    html.H3("📄 All CVEs", style={"marginBottom": "0.5rem"}),
    dash_table.DataTable(
        id="cve-table",
        columns=[{"name": i, "id": i} for i in df.columns],
        data=df.to_dict("records"),
        page_size=10,
        style_table={"overflowX": "auto"},
        style_cell={"textAlign": "left", "padding": "5px"},
        style_header={"fontWeight": "bold", "backgroundColor": "#f1f1f1"}
    )
], style={"padding": "2rem", "fontFamily": "Segoe UI, sans-serif"})

@app.callback(
    Output("cve-table", "data"),
    Input("search-btn", "n_clicks"),
    State("keyword", "value")
)
def update_table(n, keyword):
    dff = get_cve_data()
    if keyword:
        dff = dff[dff["description"].str.contains(keyword, case=False, na=False)]
    return dff.to_dict("records")

@app.callback(
    Output("prediction-output", "children"),
    Input("predict-btn", "n_clicks"),
    State("desc-input", "value")
)
def predict_severity(n, text):
    if not text:
        return ""
    X = vectorizer.transform([text])
    pred = model.predict(X)[0]
    return f"Predicted Severity: {pred}"

import plotly.express as px
from datetime import datetime

@app.callback(
    Output("severity-chart", "figure"),
    Input("search-btn", "n_clicks"),
    State("keyword", "value")
)
def update_severity_chart(n, keyword):
    dff = get_cve_data()
    if keyword:
        dff = dff[dff["description"].str.contains(keyword, case=False, na=False)]
    severity_counts = dff["severity"].value_counts().reset_index()
    severity_counts.columns = ["severity", "count"]
    fig = px.bar(severity_counts, x="severity", y="count", title="CVEs by Severity", text="count")
    fig.update_layout(xaxis_title="Severity", yaxis_title="Count")
    return fig

@app.callback(
    Output("timeline-chart", "figure"),
    Input("search-btn", "n_clicks"),
    State("keyword", "value")
)
def update_timeline_chart(n, keyword):
    dff = get_cve_data()
    if keyword:
        dff = dff[dff["description"].str.contains(keyword, case=False, na=False)]
    dff["published_date"] = pd.to_datetime(dff["published_date"], errors="coerce")
    timeline = dff.groupby(dff["published_date"].dt.date).size().reset_index(name="count")
    fig = px.line(timeline, x="published_date", y="count", title="CVEs Published Per Day")
    fig.update_layout(xaxis_title="Date", yaxis_title="Count")
    return fig


if __name__ == "__main__":
    app.run(debug=True)
