
import React from 'react';
import {  
 Resource,
 List, Datagrid, 
 SimpleForm,  Create,
 Show,  TabbedShowLayout, Tab, SimpleShowLayout,
 Edit, TabbedForm, FormTab, SimpleFormIterator,
 NumberField, BooleanField,  DateField, TextField, ReferenceField, ArrayField, SingleFieldList, UrlField,
 BooleanInput, DateInput, NumberInput, TextInput, ReferenceInput, SelectInput, ArrayInput,
} from 'react-admin';
import icon from '@material-ui/icons/SyncAlt';
export const ProvidersIcon = icon


export const ProvidersList = props => (
    <List {...props}>
        <Datagrid rowClick="show">
            <TextField source="display_name" />
            <TextField source="name" />
            <TextField source="type" />
            <ReferenceField source="space_id" reference="spaces"><TextField source="name" /></ReferenceField>
            <TextField source="id" />
        </Datagrid>
    </List>
);

const ScopesField = ({ record }) => (
    <ul>
        {record.client_scopes.map(item => (
            <li key={item}>{item}</li>
        ))}
    </ul>
)
ScopesField.defaultProps = { addLabel: true };


export const ProvidersShow = props => (
    <Show {...props}>
        <SimpleShowLayout>
            <TextField source="id" />
            <ReferenceField source="space_id" reference="spaces"><TextField source="name" /></ReferenceField>
            <TextField source="name" />
            <TextField source="type" />
            <TextField source="display_name" />
            <TextField source="client_id" />
            <TextField source="client_secret" />
            <ScopesField source="client_scopes"/>
            <UrlField source="endpoint_auth_url" />
            <UrlField source="endpoint_token_url" />
            <UrlField source="endpoint_user_info_url" />
        </SimpleShowLayout>
    </Show>
);

export const ProvidersEdit = props => (
    <Edit {...props}>
        <SimpleForm>
            <TextInput source="id" disabled />
            <ReferenceInput source="space_id" reference="spaces"><SelectInput optionText="name" disabled /></ReferenceInput>
            <TextInput source="name" />
			<SelectInput source="type" choices={[
    			{ id: 'password', name: 'Password' },
    			{ id: 'social', name: 'Social' },
			]} disabled />
            <TextInput source="display_name" />
            <TextInput source="client_id" />
            <TextInput source="client_secret" />
            <ArrayInput source="client_scopes" >
  				<SimpleFormIterator>
    				<TextInput />
  				</SimpleFormIterator>
            </ArrayInput>
            <TextInput source="endpoint_auth_url" type="url"/>
            <TextInput source="endpoint_token_url" type="url"/>
            <TextInput source="endpoint_user_info_url" type="url"/>
        </SimpleForm>
    </Edit>
);

export const ProvidersCreate = props => (
    <Create {...props}>
        <SimpleForm>
            {/*<TextInput source="id" disabled />*/}
            <ReferenceInput source="space_id" reference="spaces"><SelectInput optionText="name" /></ReferenceInput>
            <TextInput source="name" />
			<SelectInput source="type" choices={[
    			{ id: 'password', name: 'Password' },
    			{ id: 'social', name: 'Social' },
			]} />
            <TextInput source="display_name" />
            <TextInput source="client_id" />
            <TextInput source="client_secret" />
            <ArrayInput source="client_scopes" >
  				<SimpleFormIterator>
    				<TextInput />
  				</SimpleFormIterator>
            </ArrayInput>
            <TextInput source="endpoint_auth_url" type="url"/>
            <TextInput source="endpoint_token_url" type="url"/>
            <TextInput source="endpoint_user_info_url" type="url"/>
        </SimpleForm>
    </Create>
);
