// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetManagedDatabaseUserResult {
    /**
     * @return In a sharded database, indicates whether the user is created with shard DDL enabled (YES) or not (NO).
     * 
     */
    private String allShared;
    /**
     * @return The authentication mechanism for the user.
     * 
     */
    private String authentication;
    /**
     * @return Indicates whether a given user is common(Y) or local(N).
     * 
     */
    private String common;
    /**
     * @return The initial resource consumer group for the User.
     * 
     */
    private String consumerGroup;
    /**
     * @return The default collation for the user schema.
     * 
     */
    private String defaultCollation;
    /**
     * @return The default tablespace for data.
     * 
     */
    private String defaultTablespace;
    /**
     * @return Indicates whether editions have been enabled for the corresponding user (Y) or not (N).
     * 
     */
    private String editionsEnabled;
    /**
     * @return The external name of the user.
     * 
     */
    private String externalName;
    /**
     * @return In a federated sharded database, indicates whether the user is an external shard user (YES) or not (NO).
     * 
     */
    private String externalShared;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return Indicates whether the user is a common user created by an implicit application (YES) or not (NO).
     * 
     */
    private String implicit;
    /**
     * @return Indicates whether the user definition is inherited from another container (YES) or not (NO).
     * 
     */
    private String inherited;
    /**
     * @return The default local temporary tablespace for the user.
     * 
     */
    private String localTempTablespace;
    private String managedDatabaseId;
    /**
     * @return The name of the User.
     * 
     */
    private String name;
    /**
     * @return Indicates whether the user was created and is maintained by Oracle-supplied scripts (such as catalog.sql or catproc.sql).
     * 
     */
    private String oracleMaintained;
    /**
     * @return The list of existing versions of the password hashes (also known as &#34;verifiers&#34;) for the account.
     * 
     */
    private String passwordVersions;
    /**
     * @return The profile name of the user.
     * 
     */
    private String profile;
    /**
     * @return Indicates whether a user can connect directly (N) or whether the account can only be proxied (Y) by users who have proxy privileges for this account (that is, by users who have been granted the &#34;connect through&#34; privilege for this account).
     * 
     */
    private String proxyConnect;
    /**
     * @return The status of the user account.
     * 
     */
    private String status;
    /**
     * @return The name of the default tablespace for temporary tables or the name of a tablespace group.
     * 
     */
    private String tempTablespace;
    /**
     * @return The date and time the user was created.
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time of the expiration of the user account.
     * 
     */
    private String timeExpiring;
    /**
     * @return The date and time of the last user login. This column is not populated when a user connects to the database with administrative privileges, that is, AS { SYSASM | SYSBACKUP | SYSDBA | SYSDG | SYSOPER | SYSRAC | SYSKM }.
     * 
     */
    private String timeLastLogin;
    /**
     * @return The date the account was locked, if the status of the account is LOCKED.
     * 
     */
    private String timeLocked;
    /**
     * @return The date and time when the user password was last set. This column is populated only when the value of the AUTHENTICATION_TYPE column is PASSWORD. Otherwise, this column is null.
     * 
     */
    private String timePasswordChanged;
    private String userName;

    private GetManagedDatabaseUserResult() {}
    /**
     * @return In a sharded database, indicates whether the user is created with shard DDL enabled (YES) or not (NO).
     * 
     */
    public String allShared() {
        return this.allShared;
    }
    /**
     * @return The authentication mechanism for the user.
     * 
     */
    public String authentication() {
        return this.authentication;
    }
    /**
     * @return Indicates whether a given user is common(Y) or local(N).
     * 
     */
    public String common() {
        return this.common;
    }
    /**
     * @return The initial resource consumer group for the User.
     * 
     */
    public String consumerGroup() {
        return this.consumerGroup;
    }
    /**
     * @return The default collation for the user schema.
     * 
     */
    public String defaultCollation() {
        return this.defaultCollation;
    }
    /**
     * @return The default tablespace for data.
     * 
     */
    public String defaultTablespace() {
        return this.defaultTablespace;
    }
    /**
     * @return Indicates whether editions have been enabled for the corresponding user (Y) or not (N).
     * 
     */
    public String editionsEnabled() {
        return this.editionsEnabled;
    }
    /**
     * @return The external name of the user.
     * 
     */
    public String externalName() {
        return this.externalName;
    }
    /**
     * @return In a federated sharded database, indicates whether the user is an external shard user (YES) or not (NO).
     * 
     */
    public String externalShared() {
        return this.externalShared;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Indicates whether the user is a common user created by an implicit application (YES) or not (NO).
     * 
     */
    public String implicit() {
        return this.implicit;
    }
    /**
     * @return Indicates whether the user definition is inherited from another container (YES) or not (NO).
     * 
     */
    public String inherited() {
        return this.inherited;
    }
    /**
     * @return The default local temporary tablespace for the user.
     * 
     */
    public String localTempTablespace() {
        return this.localTempTablespace;
    }
    public String managedDatabaseId() {
        return this.managedDatabaseId;
    }
    /**
     * @return The name of the User.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Indicates whether the user was created and is maintained by Oracle-supplied scripts (such as catalog.sql or catproc.sql).
     * 
     */
    public String oracleMaintained() {
        return this.oracleMaintained;
    }
    /**
     * @return The list of existing versions of the password hashes (also known as &#34;verifiers&#34;) for the account.
     * 
     */
    public String passwordVersions() {
        return this.passwordVersions;
    }
    /**
     * @return The profile name of the user.
     * 
     */
    public String profile() {
        return this.profile;
    }
    /**
     * @return Indicates whether a user can connect directly (N) or whether the account can only be proxied (Y) by users who have proxy privileges for this account (that is, by users who have been granted the &#34;connect through&#34; privilege for this account).
     * 
     */
    public String proxyConnect() {
        return this.proxyConnect;
    }
    /**
     * @return The status of the user account.
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return The name of the default tablespace for temporary tables or the name of a tablespace group.
     * 
     */
    public String tempTablespace() {
        return this.tempTablespace;
    }
    /**
     * @return The date and time the user was created.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time of the expiration of the user account.
     * 
     */
    public String timeExpiring() {
        return this.timeExpiring;
    }
    /**
     * @return The date and time of the last user login. This column is not populated when a user connects to the database with administrative privileges, that is, AS { SYSASM | SYSBACKUP | SYSDBA | SYSDG | SYSOPER | SYSRAC | SYSKM }.
     * 
     */
    public String timeLastLogin() {
        return this.timeLastLogin;
    }
    /**
     * @return The date the account was locked, if the status of the account is LOCKED.
     * 
     */
    public String timeLocked() {
        return this.timeLocked;
    }
    /**
     * @return The date and time when the user password was last set. This column is populated only when the value of the AUTHENTICATION_TYPE column is PASSWORD. Otherwise, this column is null.
     * 
     */
    public String timePasswordChanged() {
        return this.timePasswordChanged;
    }
    public String userName() {
        return this.userName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabaseUserResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String allShared;
        private String authentication;
        private String common;
        private String consumerGroup;
        private String defaultCollation;
        private String defaultTablespace;
        private String editionsEnabled;
        private String externalName;
        private String externalShared;
        private String id;
        private String implicit;
        private String inherited;
        private String localTempTablespace;
        private String managedDatabaseId;
        private String name;
        private String oracleMaintained;
        private String passwordVersions;
        private String profile;
        private String proxyConnect;
        private String status;
        private String tempTablespace;
        private String timeCreated;
        private String timeExpiring;
        private String timeLastLogin;
        private String timeLocked;
        private String timePasswordChanged;
        private String userName;
        public Builder() {}
        public Builder(GetManagedDatabaseUserResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.allShared = defaults.allShared;
    	      this.authentication = defaults.authentication;
    	      this.common = defaults.common;
    	      this.consumerGroup = defaults.consumerGroup;
    	      this.defaultCollation = defaults.defaultCollation;
    	      this.defaultTablespace = defaults.defaultTablespace;
    	      this.editionsEnabled = defaults.editionsEnabled;
    	      this.externalName = defaults.externalName;
    	      this.externalShared = defaults.externalShared;
    	      this.id = defaults.id;
    	      this.implicit = defaults.implicit;
    	      this.inherited = defaults.inherited;
    	      this.localTempTablespace = defaults.localTempTablespace;
    	      this.managedDatabaseId = defaults.managedDatabaseId;
    	      this.name = defaults.name;
    	      this.oracleMaintained = defaults.oracleMaintained;
    	      this.passwordVersions = defaults.passwordVersions;
    	      this.profile = defaults.profile;
    	      this.proxyConnect = defaults.proxyConnect;
    	      this.status = defaults.status;
    	      this.tempTablespace = defaults.tempTablespace;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeExpiring = defaults.timeExpiring;
    	      this.timeLastLogin = defaults.timeLastLogin;
    	      this.timeLocked = defaults.timeLocked;
    	      this.timePasswordChanged = defaults.timePasswordChanged;
    	      this.userName = defaults.userName;
        }

        @CustomType.Setter
        public Builder allShared(String allShared) {
            this.allShared = Objects.requireNonNull(allShared);
            return this;
        }
        @CustomType.Setter
        public Builder authentication(String authentication) {
            this.authentication = Objects.requireNonNull(authentication);
            return this;
        }
        @CustomType.Setter
        public Builder common(String common) {
            this.common = Objects.requireNonNull(common);
            return this;
        }
        @CustomType.Setter
        public Builder consumerGroup(String consumerGroup) {
            this.consumerGroup = Objects.requireNonNull(consumerGroup);
            return this;
        }
        @CustomType.Setter
        public Builder defaultCollation(String defaultCollation) {
            this.defaultCollation = Objects.requireNonNull(defaultCollation);
            return this;
        }
        @CustomType.Setter
        public Builder defaultTablespace(String defaultTablespace) {
            this.defaultTablespace = Objects.requireNonNull(defaultTablespace);
            return this;
        }
        @CustomType.Setter
        public Builder editionsEnabled(String editionsEnabled) {
            this.editionsEnabled = Objects.requireNonNull(editionsEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder externalName(String externalName) {
            this.externalName = Objects.requireNonNull(externalName);
            return this;
        }
        @CustomType.Setter
        public Builder externalShared(String externalShared) {
            this.externalShared = Objects.requireNonNull(externalShared);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder implicit(String implicit) {
            this.implicit = Objects.requireNonNull(implicit);
            return this;
        }
        @CustomType.Setter
        public Builder inherited(String inherited) {
            this.inherited = Objects.requireNonNull(inherited);
            return this;
        }
        @CustomType.Setter
        public Builder localTempTablespace(String localTempTablespace) {
            this.localTempTablespace = Objects.requireNonNull(localTempTablespace);
            return this;
        }
        @CustomType.Setter
        public Builder managedDatabaseId(String managedDatabaseId) {
            this.managedDatabaseId = Objects.requireNonNull(managedDatabaseId);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder oracleMaintained(String oracleMaintained) {
            this.oracleMaintained = Objects.requireNonNull(oracleMaintained);
            return this;
        }
        @CustomType.Setter
        public Builder passwordVersions(String passwordVersions) {
            this.passwordVersions = Objects.requireNonNull(passwordVersions);
            return this;
        }
        @CustomType.Setter
        public Builder profile(String profile) {
            this.profile = Objects.requireNonNull(profile);
            return this;
        }
        @CustomType.Setter
        public Builder proxyConnect(String proxyConnect) {
            this.proxyConnect = Objects.requireNonNull(proxyConnect);
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }
        @CustomType.Setter
        public Builder tempTablespace(String tempTablespace) {
            this.tempTablespace = Objects.requireNonNull(tempTablespace);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeExpiring(String timeExpiring) {
            this.timeExpiring = Objects.requireNonNull(timeExpiring);
            return this;
        }
        @CustomType.Setter
        public Builder timeLastLogin(String timeLastLogin) {
            this.timeLastLogin = Objects.requireNonNull(timeLastLogin);
            return this;
        }
        @CustomType.Setter
        public Builder timeLocked(String timeLocked) {
            this.timeLocked = Objects.requireNonNull(timeLocked);
            return this;
        }
        @CustomType.Setter
        public Builder timePasswordChanged(String timePasswordChanged) {
            this.timePasswordChanged = Objects.requireNonNull(timePasswordChanged);
            return this;
        }
        @CustomType.Setter
        public Builder userName(String userName) {
            this.userName = Objects.requireNonNull(userName);
            return this;
        }
        public GetManagedDatabaseUserResult build() {
            final var o = new GetManagedDatabaseUserResult();
            o.allShared = allShared;
            o.authentication = authentication;
            o.common = common;
            o.consumerGroup = consumerGroup;
            o.defaultCollation = defaultCollation;
            o.defaultTablespace = defaultTablespace;
            o.editionsEnabled = editionsEnabled;
            o.externalName = externalName;
            o.externalShared = externalShared;
            o.id = id;
            o.implicit = implicit;
            o.inherited = inherited;
            o.localTempTablespace = localTempTablespace;
            o.managedDatabaseId = managedDatabaseId;
            o.name = name;
            o.oracleMaintained = oracleMaintained;
            o.passwordVersions = passwordVersions;
            o.profile = profile;
            o.proxyConnect = proxyConnect;
            o.status = status;
            o.tempTablespace = tempTablespace;
            o.timeCreated = timeCreated;
            o.timeExpiring = timeExpiring;
            o.timeLastLogin = timeLastLogin;
            o.timeLocked = timeLocked;
            o.timePasswordChanged = timePasswordChanged;
            o.userName = userName;
            return o;
        }
    }
}