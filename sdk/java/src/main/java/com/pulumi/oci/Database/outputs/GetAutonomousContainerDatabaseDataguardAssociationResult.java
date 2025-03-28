// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.outputs.GetAutonomousContainerDatabaseDataguardAssociationPeerAutonomousContainerDatabaseBackupConfig;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAutonomousContainerDatabaseDataguardAssociationResult {
    /**
     * @return The lag time between updates to the primary Autonomous Container Database and application of the redo data on the standby Autonomous Container Database, as computed by the reporting database.  Example: `9 seconds`
     * 
     */
    private String applyLag;
    /**
     * @return The rate at which redo logs are synchronized between the associated Autonomous Container Databases.  Example: `180 Mb per second`
     * 
     */
    private String applyRate;
    private String autonomousContainerDatabaseDataguardAssociationId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Container Database that has a relationship with the peer Autonomous Container Database. Used only by Autonomous Database on Dedicated Exadata Infrastructure.
     * 
     */
    private String autonomousContainerDatabaseId;
    /**
     * @return The lag time for my preference based on data loss tolerance in seconds.
     * 
     */
    private Integer fastStartFailOverLagLimitInSeconds;
    /**
     * @return The OCID of the Autonomous Data Guard created for a given Autonomous Container Database.
     * 
     */
    private String id;
    /**
     * @return Indicates whether Automatic Failover is enabled for Autonomous Container Database Dataguard Association. Output DataType: boolean. Example : is_automatic_failover_enabled = true.
     * 
     */
    private Boolean isAutomaticFailoverEnabled;
    /**
     * @return Additional information about the current lifecycleState, if available.
     * 
     */
    private String lifecycleDetails;
    private Integer migrateTrigger;
    private List<GetAutonomousContainerDatabaseDataguardAssociationPeerAutonomousContainerDatabaseBackupConfig> peerAutonomousContainerDatabaseBackupConfigs;
    private String peerAutonomousContainerDatabaseCompartmentId;
    /**
     * @return The OCID of the peer Autonomous Container Database-Autonomous Data Guard association.
     * 
     */
    private String peerAutonomousContainerDatabaseDataguardAssociationId;
    private String peerAutonomousContainerDatabaseDisplayName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer Autonomous Container Database.
     * 
     */
    private String peerAutonomousContainerDatabaseId;
    private String peerAutonomousVmClusterId;
    private String peerCloudAutonomousVmClusterId;
    private String peerDbUniqueName;
    /**
     * @return The current state of the Autonomous Container Database.
     * 
     */
    private String peerLifecycleState;
    /**
     * @return The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled.
     * 
     */
    private String peerRole;
    /**
     * @return The protection mode of this Autonomous Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
     * 
     */
    private String protectionMode;
    /**
     * @return The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled.
     * 
     */
    private String role;
    private Integer standbyMaintenanceBufferInDays;
    /**
     * @return The current state of Autonomous Data Guard.
     * 
     */
    private String state;
    /**
     * @return The date and time the Autonomous DataGuard association was created.
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time when the last role change action happened.
     * 
     */
    private String timeLastRoleChanged;
    /**
     * @return The date and time of the last update to the apply lag, apply rate, and transport lag values.
     * 
     */
    private String timeLastSynced;
    /**
     * @return The approximate number of seconds of redo data not yet available on the standby Autonomous Container Database, as computed by the reporting database.  Example: `7 seconds`
     * 
     */
    private String transportLag;

    private GetAutonomousContainerDatabaseDataguardAssociationResult() {}
    /**
     * @return The lag time between updates to the primary Autonomous Container Database and application of the redo data on the standby Autonomous Container Database, as computed by the reporting database.  Example: `9 seconds`
     * 
     */
    public String applyLag() {
        return this.applyLag;
    }
    /**
     * @return The rate at which redo logs are synchronized between the associated Autonomous Container Databases.  Example: `180 Mb per second`
     * 
     */
    public String applyRate() {
        return this.applyRate;
    }
    public String autonomousContainerDatabaseDataguardAssociationId() {
        return this.autonomousContainerDatabaseDataguardAssociationId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Container Database that has a relationship with the peer Autonomous Container Database. Used only by Autonomous Database on Dedicated Exadata Infrastructure.
     * 
     */
    public String autonomousContainerDatabaseId() {
        return this.autonomousContainerDatabaseId;
    }
    /**
     * @return The lag time for my preference based on data loss tolerance in seconds.
     * 
     */
    public Integer fastStartFailOverLagLimitInSeconds() {
        return this.fastStartFailOverLagLimitInSeconds;
    }
    /**
     * @return The OCID of the Autonomous Data Guard created for a given Autonomous Container Database.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Indicates whether Automatic Failover is enabled for Autonomous Container Database Dataguard Association. Output DataType: boolean. Example : is_automatic_failover_enabled = true.
     * 
     */
    public Boolean isAutomaticFailoverEnabled() {
        return this.isAutomaticFailoverEnabled;
    }
    /**
     * @return Additional information about the current lifecycleState, if available.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    public Integer migrateTrigger() {
        return this.migrateTrigger;
    }
    public List<GetAutonomousContainerDatabaseDataguardAssociationPeerAutonomousContainerDatabaseBackupConfig> peerAutonomousContainerDatabaseBackupConfigs() {
        return this.peerAutonomousContainerDatabaseBackupConfigs;
    }
    public String peerAutonomousContainerDatabaseCompartmentId() {
        return this.peerAutonomousContainerDatabaseCompartmentId;
    }
    /**
     * @return The OCID of the peer Autonomous Container Database-Autonomous Data Guard association.
     * 
     */
    public String peerAutonomousContainerDatabaseDataguardAssociationId() {
        return this.peerAutonomousContainerDatabaseDataguardAssociationId;
    }
    public String peerAutonomousContainerDatabaseDisplayName() {
        return this.peerAutonomousContainerDatabaseDisplayName;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer Autonomous Container Database.
     * 
     */
    public String peerAutonomousContainerDatabaseId() {
        return this.peerAutonomousContainerDatabaseId;
    }
    public String peerAutonomousVmClusterId() {
        return this.peerAutonomousVmClusterId;
    }
    public String peerCloudAutonomousVmClusterId() {
        return this.peerCloudAutonomousVmClusterId;
    }
    public String peerDbUniqueName() {
        return this.peerDbUniqueName;
    }
    /**
     * @return The current state of the Autonomous Container Database.
     * 
     */
    public String peerLifecycleState() {
        return this.peerLifecycleState;
    }
    /**
     * @return The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled.
     * 
     */
    public String peerRole() {
        return this.peerRole;
    }
    /**
     * @return The protection mode of this Autonomous Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
     * 
     */
    public String protectionMode() {
        return this.protectionMode;
    }
    /**
     * @return The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled.
     * 
     */
    public String role() {
        return this.role;
    }
    public Integer standbyMaintenanceBufferInDays() {
        return this.standbyMaintenanceBufferInDays;
    }
    /**
     * @return The current state of Autonomous Data Guard.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the Autonomous DataGuard association was created.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time when the last role change action happened.
     * 
     */
    public String timeLastRoleChanged() {
        return this.timeLastRoleChanged;
    }
    /**
     * @return The date and time of the last update to the apply lag, apply rate, and transport lag values.
     * 
     */
    public String timeLastSynced() {
        return this.timeLastSynced;
    }
    /**
     * @return The approximate number of seconds of redo data not yet available on the standby Autonomous Container Database, as computed by the reporting database.  Example: `7 seconds`
     * 
     */
    public String transportLag() {
        return this.transportLag;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutonomousContainerDatabaseDataguardAssociationResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String applyLag;
        private String applyRate;
        private String autonomousContainerDatabaseDataguardAssociationId;
        private String autonomousContainerDatabaseId;
        private Integer fastStartFailOverLagLimitInSeconds;
        private String id;
        private Boolean isAutomaticFailoverEnabled;
        private String lifecycleDetails;
        private Integer migrateTrigger;
        private List<GetAutonomousContainerDatabaseDataguardAssociationPeerAutonomousContainerDatabaseBackupConfig> peerAutonomousContainerDatabaseBackupConfigs;
        private String peerAutonomousContainerDatabaseCompartmentId;
        private String peerAutonomousContainerDatabaseDataguardAssociationId;
        private String peerAutonomousContainerDatabaseDisplayName;
        private String peerAutonomousContainerDatabaseId;
        private String peerAutonomousVmClusterId;
        private String peerCloudAutonomousVmClusterId;
        private String peerDbUniqueName;
        private String peerLifecycleState;
        private String peerRole;
        private String protectionMode;
        private String role;
        private Integer standbyMaintenanceBufferInDays;
        private String state;
        private String timeCreated;
        private String timeLastRoleChanged;
        private String timeLastSynced;
        private String transportLag;
        public Builder() {}
        public Builder(GetAutonomousContainerDatabaseDataguardAssociationResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applyLag = defaults.applyLag;
    	      this.applyRate = defaults.applyRate;
    	      this.autonomousContainerDatabaseDataguardAssociationId = defaults.autonomousContainerDatabaseDataguardAssociationId;
    	      this.autonomousContainerDatabaseId = defaults.autonomousContainerDatabaseId;
    	      this.fastStartFailOverLagLimitInSeconds = defaults.fastStartFailOverLagLimitInSeconds;
    	      this.id = defaults.id;
    	      this.isAutomaticFailoverEnabled = defaults.isAutomaticFailoverEnabled;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.migrateTrigger = defaults.migrateTrigger;
    	      this.peerAutonomousContainerDatabaseBackupConfigs = defaults.peerAutonomousContainerDatabaseBackupConfigs;
    	      this.peerAutonomousContainerDatabaseCompartmentId = defaults.peerAutonomousContainerDatabaseCompartmentId;
    	      this.peerAutonomousContainerDatabaseDataguardAssociationId = defaults.peerAutonomousContainerDatabaseDataguardAssociationId;
    	      this.peerAutonomousContainerDatabaseDisplayName = defaults.peerAutonomousContainerDatabaseDisplayName;
    	      this.peerAutonomousContainerDatabaseId = defaults.peerAutonomousContainerDatabaseId;
    	      this.peerAutonomousVmClusterId = defaults.peerAutonomousVmClusterId;
    	      this.peerCloudAutonomousVmClusterId = defaults.peerCloudAutonomousVmClusterId;
    	      this.peerDbUniqueName = defaults.peerDbUniqueName;
    	      this.peerLifecycleState = defaults.peerLifecycleState;
    	      this.peerRole = defaults.peerRole;
    	      this.protectionMode = defaults.protectionMode;
    	      this.role = defaults.role;
    	      this.standbyMaintenanceBufferInDays = defaults.standbyMaintenanceBufferInDays;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeLastRoleChanged = defaults.timeLastRoleChanged;
    	      this.timeLastSynced = defaults.timeLastSynced;
    	      this.transportLag = defaults.transportLag;
        }

        @CustomType.Setter
        public Builder applyLag(String applyLag) {
            if (applyLag == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "applyLag");
            }
            this.applyLag = applyLag;
            return this;
        }
        @CustomType.Setter
        public Builder applyRate(String applyRate) {
            if (applyRate == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "applyRate");
            }
            this.applyRate = applyRate;
            return this;
        }
        @CustomType.Setter
        public Builder autonomousContainerDatabaseDataguardAssociationId(String autonomousContainerDatabaseDataguardAssociationId) {
            if (autonomousContainerDatabaseDataguardAssociationId == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "autonomousContainerDatabaseDataguardAssociationId");
            }
            this.autonomousContainerDatabaseDataguardAssociationId = autonomousContainerDatabaseDataguardAssociationId;
            return this;
        }
        @CustomType.Setter
        public Builder autonomousContainerDatabaseId(String autonomousContainerDatabaseId) {
            if (autonomousContainerDatabaseId == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "autonomousContainerDatabaseId");
            }
            this.autonomousContainerDatabaseId = autonomousContainerDatabaseId;
            return this;
        }
        @CustomType.Setter
        public Builder fastStartFailOverLagLimitInSeconds(Integer fastStartFailOverLagLimitInSeconds) {
            if (fastStartFailOverLagLimitInSeconds == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "fastStartFailOverLagLimitInSeconds");
            }
            this.fastStartFailOverLagLimitInSeconds = fastStartFailOverLagLimitInSeconds;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isAutomaticFailoverEnabled(Boolean isAutomaticFailoverEnabled) {
            if (isAutomaticFailoverEnabled == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "isAutomaticFailoverEnabled");
            }
            this.isAutomaticFailoverEnabled = isAutomaticFailoverEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder migrateTrigger(Integer migrateTrigger) {
            if (migrateTrigger == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "migrateTrigger");
            }
            this.migrateTrigger = migrateTrigger;
            return this;
        }
        @CustomType.Setter
        public Builder peerAutonomousContainerDatabaseBackupConfigs(List<GetAutonomousContainerDatabaseDataguardAssociationPeerAutonomousContainerDatabaseBackupConfig> peerAutonomousContainerDatabaseBackupConfigs) {
            if (peerAutonomousContainerDatabaseBackupConfigs == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "peerAutonomousContainerDatabaseBackupConfigs");
            }
            this.peerAutonomousContainerDatabaseBackupConfigs = peerAutonomousContainerDatabaseBackupConfigs;
            return this;
        }
        public Builder peerAutonomousContainerDatabaseBackupConfigs(GetAutonomousContainerDatabaseDataguardAssociationPeerAutonomousContainerDatabaseBackupConfig... peerAutonomousContainerDatabaseBackupConfigs) {
            return peerAutonomousContainerDatabaseBackupConfigs(List.of(peerAutonomousContainerDatabaseBackupConfigs));
        }
        @CustomType.Setter
        public Builder peerAutonomousContainerDatabaseCompartmentId(String peerAutonomousContainerDatabaseCompartmentId) {
            if (peerAutonomousContainerDatabaseCompartmentId == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "peerAutonomousContainerDatabaseCompartmentId");
            }
            this.peerAutonomousContainerDatabaseCompartmentId = peerAutonomousContainerDatabaseCompartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder peerAutonomousContainerDatabaseDataguardAssociationId(String peerAutonomousContainerDatabaseDataguardAssociationId) {
            if (peerAutonomousContainerDatabaseDataguardAssociationId == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "peerAutonomousContainerDatabaseDataguardAssociationId");
            }
            this.peerAutonomousContainerDatabaseDataguardAssociationId = peerAutonomousContainerDatabaseDataguardAssociationId;
            return this;
        }
        @CustomType.Setter
        public Builder peerAutonomousContainerDatabaseDisplayName(String peerAutonomousContainerDatabaseDisplayName) {
            if (peerAutonomousContainerDatabaseDisplayName == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "peerAutonomousContainerDatabaseDisplayName");
            }
            this.peerAutonomousContainerDatabaseDisplayName = peerAutonomousContainerDatabaseDisplayName;
            return this;
        }
        @CustomType.Setter
        public Builder peerAutonomousContainerDatabaseId(String peerAutonomousContainerDatabaseId) {
            if (peerAutonomousContainerDatabaseId == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "peerAutonomousContainerDatabaseId");
            }
            this.peerAutonomousContainerDatabaseId = peerAutonomousContainerDatabaseId;
            return this;
        }
        @CustomType.Setter
        public Builder peerAutonomousVmClusterId(String peerAutonomousVmClusterId) {
            if (peerAutonomousVmClusterId == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "peerAutonomousVmClusterId");
            }
            this.peerAutonomousVmClusterId = peerAutonomousVmClusterId;
            return this;
        }
        @CustomType.Setter
        public Builder peerCloudAutonomousVmClusterId(String peerCloudAutonomousVmClusterId) {
            if (peerCloudAutonomousVmClusterId == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "peerCloudAutonomousVmClusterId");
            }
            this.peerCloudAutonomousVmClusterId = peerCloudAutonomousVmClusterId;
            return this;
        }
        @CustomType.Setter
        public Builder peerDbUniqueName(String peerDbUniqueName) {
            if (peerDbUniqueName == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "peerDbUniqueName");
            }
            this.peerDbUniqueName = peerDbUniqueName;
            return this;
        }
        @CustomType.Setter
        public Builder peerLifecycleState(String peerLifecycleState) {
            if (peerLifecycleState == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "peerLifecycleState");
            }
            this.peerLifecycleState = peerLifecycleState;
            return this;
        }
        @CustomType.Setter
        public Builder peerRole(String peerRole) {
            if (peerRole == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "peerRole");
            }
            this.peerRole = peerRole;
            return this;
        }
        @CustomType.Setter
        public Builder protectionMode(String protectionMode) {
            if (protectionMode == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "protectionMode");
            }
            this.protectionMode = protectionMode;
            return this;
        }
        @CustomType.Setter
        public Builder role(String role) {
            if (role == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "role");
            }
            this.role = role;
            return this;
        }
        @CustomType.Setter
        public Builder standbyMaintenanceBufferInDays(Integer standbyMaintenanceBufferInDays) {
            if (standbyMaintenanceBufferInDays == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "standbyMaintenanceBufferInDays");
            }
            this.standbyMaintenanceBufferInDays = standbyMaintenanceBufferInDays;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeLastRoleChanged(String timeLastRoleChanged) {
            if (timeLastRoleChanged == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "timeLastRoleChanged");
            }
            this.timeLastRoleChanged = timeLastRoleChanged;
            return this;
        }
        @CustomType.Setter
        public Builder timeLastSynced(String timeLastSynced) {
            if (timeLastSynced == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "timeLastSynced");
            }
            this.timeLastSynced = timeLastSynced;
            return this;
        }
        @CustomType.Setter
        public Builder transportLag(String transportLag) {
            if (transportLag == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabaseDataguardAssociationResult", "transportLag");
            }
            this.transportLag = transportLag;
            return this;
        }
        public GetAutonomousContainerDatabaseDataguardAssociationResult build() {
            final var _resultValue = new GetAutonomousContainerDatabaseDataguardAssociationResult();
            _resultValue.applyLag = applyLag;
            _resultValue.applyRate = applyRate;
            _resultValue.autonomousContainerDatabaseDataguardAssociationId = autonomousContainerDatabaseDataguardAssociationId;
            _resultValue.autonomousContainerDatabaseId = autonomousContainerDatabaseId;
            _resultValue.fastStartFailOverLagLimitInSeconds = fastStartFailOverLagLimitInSeconds;
            _resultValue.id = id;
            _resultValue.isAutomaticFailoverEnabled = isAutomaticFailoverEnabled;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.migrateTrigger = migrateTrigger;
            _resultValue.peerAutonomousContainerDatabaseBackupConfigs = peerAutonomousContainerDatabaseBackupConfigs;
            _resultValue.peerAutonomousContainerDatabaseCompartmentId = peerAutonomousContainerDatabaseCompartmentId;
            _resultValue.peerAutonomousContainerDatabaseDataguardAssociationId = peerAutonomousContainerDatabaseDataguardAssociationId;
            _resultValue.peerAutonomousContainerDatabaseDisplayName = peerAutonomousContainerDatabaseDisplayName;
            _resultValue.peerAutonomousContainerDatabaseId = peerAutonomousContainerDatabaseId;
            _resultValue.peerAutonomousVmClusterId = peerAutonomousVmClusterId;
            _resultValue.peerCloudAutonomousVmClusterId = peerCloudAutonomousVmClusterId;
            _resultValue.peerDbUniqueName = peerDbUniqueName;
            _resultValue.peerLifecycleState = peerLifecycleState;
            _resultValue.peerRole = peerRole;
            _resultValue.protectionMode = protectionMode;
            _resultValue.role = role;
            _resultValue.standbyMaintenanceBufferInDays = standbyMaintenanceBufferInDays;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeLastRoleChanged = timeLastRoleChanged;
            _resultValue.timeLastSynced = timeLastSynced;
            _resultValue.transportLag = transportLag;
            return _resultValue;
        }
    }
}
