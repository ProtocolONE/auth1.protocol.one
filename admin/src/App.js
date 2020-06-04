// in src/App.js
import React from 'react';
import { fetchUtils, Admin, Resource, ListGuesser, ShowGuesser, EditGuesser,
 List, Datagrid, TextField, ReferenceField, Filter, ReferenceInput, SelectInput, SimpleForm, TextInput, Create,
 NumberField, BooleanField, SimpleShowLayout, Show, DateField , TabbedShowLayout, Tab, 
 Edit, TabbedForm, FormTab, BooleanInput, DateInput, NumberInput} from 'react-admin';
import jsonServerProvider from 'ra-data-json-server';
import simpleRestProvider from 'ra-data-simple-rest';
import { createMuiTheme } from '@material-ui/core/styles';
import UsersIcon from '@material-ui/icons/PeopleAlt';
import AppsIcon from '@material-ui/icons/Tablet';

import { SpaceIcon, SpaceList, SpaceShow, SpaceEdit, SpaceCreate } from './components/spaces.jsx'
import { ProvidersIcon, ProvidersList, ProvidersShow, ProvidersEdit, ProvidersCreate } from './components/providers.jsx'


const theme = createMuiTheme({
  palette: {
    type: 'dark', // Switching the dark mode on is a single property value change.
  },
});

const httpClient = (url, options = {}) => {
    if (!options.headers) {
        options.headers = new Headers({ Accept: 'application/json' });
    }
    // const token = btoa('admin:password');
    // options.headers.set('Authorization', `Basic ${token}`);
    return fetchUtils.fetchJson(url, options);
}


// const dataProvider = jsonServerProvider('http://localhost:6001/api', httpClient);
const dataProvider = jsonServerProvider('/api', httpClient);
const App = () => (
    <Admin dataProvider={dataProvider} theme={theme}>
        <Resource name="spaces" icon={SpaceIcon} list={SpaceList} show={SpaceShow} edit={SpaceEdit} create={SpaceCreate} />
        <Resource name="identity_providers" icon={ProvidersIcon} list={ProvidersList} show={ProvidersShow} edit={ProvidersEdit} create={ProvidersCreate} />
        <Resource name="users" icon={UsersIcon} list={ListGuesser} show={ShowGuesser} edit={EditGuesser} />
        <Resource name="apps" icon={AppsIcon} list={ListGuesser} show={ShowGuesser} edit={EditGuesser} />
    </Admin>
);


export default App;
