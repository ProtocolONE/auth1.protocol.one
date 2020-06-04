
import React from 'react';
import {  
 Resource,
 List, Datagrid, 
 SimpleForm,  Create,
 Show,  TabbedShowLayout, Tab,
 Edit, TabbedForm, FormTab,
 NumberField, BooleanField,  DateField, TextField, 
 BooleanInput, DateInput, NumberInput, TextInput,
} from 'react-admin';
import spaceIcon from '@material-ui/icons/Book';
export const SpaceIcon = spaceIcon

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

export const SpaceEdit = props => (
    <Edit {...props}>
        <TabbedForm>
            <FormTab label="Summary">
                <TextInput disabled source="id" />
                <TextInput source="name" />
                <TextInput source="description" />
                <BooleanInput source="unique_usernames" />
                <BooleanInput source="requires_captcha" />
                <DateInput disabled source="created_at" />
                <DateInput disabled source="updated_at" />
            </FormTab>
            <FormTab label="Password Settings">
                <NumberInput source="password_settings.bcrypt_cost"  label="BCrypt Cost"/>
                <NumberInput source="password_settings.min" label="Min" />
                <NumberInput source="password_settings.max" label="Max" />
                <NumberInput source="password_settings.token_length" label="Token Length" />
                <NumberInput source="password_settings.token_ttl" label="Token TTL" />
                <BooleanInput source="password_settings.require_letter" label="Require Letter" />
                <BooleanInput source="password_settings.require_upper" label="Require Upper" />
                <BooleanInput source="password_settings.require_number" label="Require Number" />
                <BooleanInput source="password_settings.require_special" label="Require Special" />
            </FormTab>
        </TabbedForm>
    </Edit>
);

