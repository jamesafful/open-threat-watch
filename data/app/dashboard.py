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
    html.H1("OpenThreatWatch – CVE Dashboard"),

    dcc.Input(id="keyword", type="text", placeholder="Search CVEs...", debounce=True),
    html.Button("Search", id="search-btn"),

    dash_table.DataTable(
        id="cve-table",
        columns=[{"name": i, "id": i} for i in df.columns],
        data=df.to_dict("records"),
        page_size=10,
        style_table={"overflowX": "auto"},
        style_cell={"textAlign": "left"}
    ),

    html.Hr(),
    html.H3("Predict Severity of New Description"),
    dcc.Textarea(id="desc-input", style={"width": "100%"}, rows=4),
    html.Button("Predict", id="predict-btn"),
    html.Div(id="prediction-output", style={"marginTop": 20, "fontWeight": "bold"})
])

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

if __name__ == "__main__":
    app.run(debug=True)
