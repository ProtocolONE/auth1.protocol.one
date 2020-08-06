
import React from 'react';
import {
    SimpleForm,
    Edit,  TextInput, ArrayInput, SimpleFormIterator
} from 'react-admin';

export const UserEdit = props => (
    <Edit {...props}>
        <SimpleForm>

            <TextInput disabled source="id" />
            <TextInput source="name" />
            <TextInput source="email" />

            <ArrayInput source="roles">
                <SimpleFormIterator>
                    <TextInput />
                </SimpleFormIterator>
            </ArrayInput>

        </SimpleForm>
    </Edit>
);