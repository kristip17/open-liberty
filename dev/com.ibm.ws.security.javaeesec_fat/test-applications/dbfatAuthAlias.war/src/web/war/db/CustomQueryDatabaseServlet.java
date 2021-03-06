/*******************************************************************************
 * Copyright (c) 2017 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package web.war.db;

import java.sql.Connection;
import java.sql.Statement;

import javax.naming.InitialContext;
import javax.servlet.ServletException;
import javax.sql.DataSource;

import com.ibm.ws.security.javaeesec.cdi.beans.hash.Pbkdf2PasswordHashImpl;
import com.ibm.ws.security.javaeesec.fat_helper.Constants;

import componenttest.app.FATDatabaseServlet;

public class CustomQueryDatabaseServlet extends FATDatabaseServlet {
    private static final long serialVersionUID = 6698194309425789687L;

    private final String callerTable = "callertable";
    private final String callerGroups = "callertable_groups";

    @SuppressWarnings("restriction")
    @Override
    public void init() throws ServletException {
        System.out.println("Creating database for DatabaseIdentityStore: derby1fat");
        try {
            DataSource ds = (DataSource) new InitialContext().lookup("jdbc/derby1fat");

            FATDatabaseServlet.createTable(ds, callerTable, "name varchar(30), password varchar(300)");

            FATDatabaseServlet.createTable(ds, callerGroups, "group_name VARCHAR(36), caller_name VARCHAR(36)");

            Pbkdf2PasswordHashImpl pphi = new Pbkdf2PasswordHashImpl();
            String testpwd = pphi.generate((new String("pwd")).toCharArray());
            String testpwd2 = pphi.generate((new String("pwd2")).toCharArray());

            Connection conn = ds.getConnection();
            Statement stmt1 = conn.createStatement();
            stmt1.executeUpdate("insert into " + callerTable + " (password, name) values ('" + testpwd + "' , '" + Constants.DB_USER1 + "')");
            stmt1.close();

            stmt1 = conn.createStatement();
            stmt1.executeUpdate("insert into " + callerGroups + " (group_name, caller_name) values ('" + Constants.DB_GROUP2 + "' , '" + Constants.DB_USER1 + "')");
            stmt1.close();

            stmt1 = conn.createStatement();
            stmt1.executeUpdate("insert into " + callerTable + " (password, name) values ('" + testpwd2 + "' , '" + Constants.DB_USER2 + "')");
            stmt1.close();

            stmt1 = conn.createStatement();
            stmt1.executeUpdate("insert into " + callerGroups + " (group_name, caller_name) values ('" + Constants.DB_GROUP3 + "' , '" + Constants.DB_USER2 + "')");
            stmt1.close();

        } catch (Exception e) {
            System.out.println("Failed to create database for DatabaseIdentityStore: " + e.getMessage());
            e.printStackTrace();
        }
        System.out.println("Created database for DatabaseIdentityStore");
    }

}
