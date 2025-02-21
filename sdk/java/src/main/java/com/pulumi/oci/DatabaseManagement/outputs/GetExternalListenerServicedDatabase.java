// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetExternalListenerServicedDatabase {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external database resides.
     * 
     */
    private String compartmentId;
    /**
     * @return The subtype of Oracle Database. Indicates whether the database is a Container Database, Pluggable Database, Non-container Database, Autonomous Database, or Autonomous Container Database.
     * 
     */
    private String databaseSubType;
    /**
     * @return The type of Oracle Database installation.
     * 
     */
    private String databaseType;
    /**
     * @return The unique name of the external database.
     * 
     */
    private String dbUniqueName;
    /**
     * @return The user-friendly name for the database. The name does not have to be unique.
     * 
     */
    private String displayName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database.
     * 
     */
    private String id;
    /**
     * @return Indicates whether the database is a Managed Database or not.
     * 
     */
    private Boolean isManaged;

    private GetExternalListenerServicedDatabase() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external database resides.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The subtype of Oracle Database. Indicates whether the database is a Container Database, Pluggable Database, Non-container Database, Autonomous Database, or Autonomous Container Database.
     * 
     */
    public String databaseSubType() {
        return this.databaseSubType;
    }
    /**
     * @return The type of Oracle Database installation.
     * 
     */
    public String databaseType() {
        return this.databaseType;
    }
    /**
     * @return The unique name of the external database.
     * 
     */
    public String dbUniqueName() {
        return this.dbUniqueName;
    }
    /**
     * @return The user-friendly name for the database. The name does not have to be unique.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Indicates whether the database is a Managed Database or not.
     * 
     */
    public Boolean isManaged() {
        return this.isManaged;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExternalListenerServicedDatabase defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private String databaseSubType;
        private String databaseType;
        private String dbUniqueName;
        private String displayName;
        private String id;
        private Boolean isManaged;
        public Builder() {}
        public Builder(GetExternalListenerServicedDatabase defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.databaseSubType = defaults.databaseSubType;
    	      this.databaseType = defaults.databaseType;
    	      this.dbUniqueName = defaults.dbUniqueName;
    	      this.displayName = defaults.displayName;
    	      this.id = defaults.id;
    	      this.isManaged = defaults.isManaged;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetExternalListenerServicedDatabase", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder databaseSubType(String databaseSubType) {
            if (databaseSubType == null) {
              throw new MissingRequiredPropertyException("GetExternalListenerServicedDatabase", "databaseSubType");
            }
            this.databaseSubType = databaseSubType;
            return this;
        }
        @CustomType.Setter
        public Builder databaseType(String databaseType) {
            if (databaseType == null) {
              throw new MissingRequiredPropertyException("GetExternalListenerServicedDatabase", "databaseType");
            }
            this.databaseType = databaseType;
            return this;
        }
        @CustomType.Setter
        public Builder dbUniqueName(String dbUniqueName) {
            if (dbUniqueName == null) {
              throw new MissingRequiredPropertyException("GetExternalListenerServicedDatabase", "dbUniqueName");
            }
            this.dbUniqueName = dbUniqueName;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetExternalListenerServicedDatabase", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetExternalListenerServicedDatabase", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isManaged(Boolean isManaged) {
            if (isManaged == null) {
              throw new MissingRequiredPropertyException("GetExternalListenerServicedDatabase", "isManaged");
            }
            this.isManaged = isManaged;
            return this;
        }
        public GetExternalListenerServicedDatabase build() {
            final var _resultValue = new GetExternalListenerServicedDatabase();
            _resultValue.compartmentId = compartmentId;
            _resultValue.databaseSubType = databaseSubType;
            _resultValue.databaseType = databaseType;
            _resultValue.dbUniqueName = dbUniqueName;
            _resultValue.displayName = displayName;
            _resultValue.id = id;
            _resultValue.isManaged = isManaged;
            return _resultValue;
        }
    }
}
