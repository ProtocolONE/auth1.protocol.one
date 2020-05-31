// in src/App.js
import React from 'react';
import { fetchUtils, Admin, Resource, ListGuesser, ShowGuesser, EditGuesser } from 'react-admin';
import { List, Datagrid, TextField, ReferenceField, Filter, ReferenceInput, SelectInput } from 'react-admin';
import jsonServerProvider from 'ra-data-json-server';
import simpleRestProvider from 'ra-data-simple-rest';
import { createMuiTheme } from '@material-ui/core/styles';

const theme = createMuiTheme({
  palette: {
    type: 'dark', // Switching the dark mode on is a single property value change.
  },
});

const httpClient = (url, options = {}) => {
    if (!options.headers) {
        options.headers = new Headers({ Accept: 'application/json' });
    }
    const token = btoa('admin:password');
    options.headers.set('Authorization', `Basic ${token}`);
    return fetchUtils.fetchJson(url, options);
}

const dataProvider = jsonServerProvider('/api', httpClient);
const App = () => (
    <Admin dataProvider={dataProvider} theme={theme}>
        <Resource name="spaces" list={ListGuesser} show={ShowGuesser} edit={EditGuesser} />
        <Resource name="identity_providers" list={ListGuesser} show={ShowGuesser} edit={EditGuesser} />
    </Admin>
);


export default App;
