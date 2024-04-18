import plotly.io as pio
import dash_bootstrap_components as dbc
from dash import page_container

plotly_template_dark = pio.templates["plotly_dark"]
plotly_template_dark.layout.update({
    'paper_bgcolor': 'rgba(31,34,37,255)',
    'plot_bgcolor': 'rgba(43,48,53,255)',
})
external_stylesheets = [dbc.themes.BOOTSTRAP, dbc.icons.FONT_AWESOME]
page_container = page_container

print('*'*100)
print('container')
print(page_container)
print('*'*100)
