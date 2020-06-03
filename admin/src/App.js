// in src/App.js
import React from 'react';
import { fetchUtils, Admin, Resource, ListGuesser, ShowGuesser, EditGuesser,
 List, Datagrid, TextField, ReferenceField, Filter, ReferenceInput, SelectInput, SimpleForm, TextInput, Create,
 NumberField, BooleanField, SimpleShowLayout, Show, DateField , TabbedShowLayout, Tab} from 'react-admin';
import jsonServerProvider from 'ra-data-json-server';
import simpleRestProvider from 'ra-data-simple-rest';
import { createMuiTheme } from '@material-ui/core/styles';
import SpaceIcon from '@material-ui/icons/Book';
import ProvidersIcon from '@material-ui/icons/SyncAlt';
import UsersIcon from '@material-ui/icons/PeopleAlt';
import AppsIcon from '@material-ui/icons/Tablet';


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

export const SpaceCreate = (props) => (
    <Create {...props}>
        <SimpleForm>
            <TextInput source="name" />
            <TextInput source="description" options={{ multiLine: true }} />
        </SimpleForm>
    </Create>
);

export const SpaceList = props => (
    <List {...props}>
        <Datagrid rowClick="show">
            <TextField source="name" />
            <TextField source="description" />
            <TextField source="id" />
            <TextField source="created_at" />
            <TextField source="updated_at" />
        </Datagrid>
    </List>
);

export const SpaceShow = props => (
    <Show {...props}>
        <TabbedShowLayout>
            <Tab label="Summary">
                <TextField source="id" />
                <TextField source="name" />
                <TextField source="description" />
                <BooleanField source="unique_usernames" />
                <BooleanField source="requires_captcha" />
                <DateField source="created_at" />
                <DateField source="updated_at" />
            </Tab>
            <Tab label="Password Settings">
                <NumberField source="password_settings.bcrypt_cost"  label="BCrypt Cost"/>
                <NumberField source="password_settings.min" label="Min" />
                <NumberField source="password_settings.max" label="Max" />
                <NumberField source="password_settings.token_length" label="Token Length" />
                <NumberField source="password_settings.token_ttl" label="Token TTL" />
                <BooleanField source="password_settings.require_letter" label="Require Letter" />
                <BooleanField source="password_settings.require_upper" label="Require Upper" />
                <BooleanField source="password_settings.require_number" label="Require Number" />
                <BooleanField source="password_settings.require_special" label="Require Special" />
            </Tab>
        </TabbedShowLayout>
    </Show>
);


// const dataProvider = jsonServerProvider('http://localhost:6001/api', httpClient);
const dataProvider = jsonServerProvider('/api', httpClient);
const App = () => (
    <Admin dataProvider={dataProvider} theme={theme}>
        <Resource icon={SpaceIcon} name="spaces" list={SpaceList} show={SpaceShow} edit={EditGuesser} create={SpaceCreate} />
        <Resource name="identity_providers" icon={ProvidersIcon} list={ListGuesser} show={ShowGuesser} edit={EditGuesser} />
        <Resource name="users" icon={UsersIcon} list={ListGuesser} show={ShowGuesser} edit={EditGuesser} />
        <Resource name="apps" icon={AppsIcon} list={ListGuesser} show={ShowGuesser} edit={EditGuesser} />
    </Admin>
);


export default App;
