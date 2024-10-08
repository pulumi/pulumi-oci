// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ApmSynthetics.outputs.GetOnPremiseVantagePointWorkerIdentityInfo;
import com.pulumi.oci.ApmSynthetics.outputs.GetOnPremiseVantagePointWorkerMonitorList;
import com.pulumi.oci.ApmSynthetics.outputs.GetOnPremiseVantagePointWorkerVersionDetail;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetOnPremiseVantagePointWorkerResult {
    private String apmDomainId;
    /**
     * @return Configuration details of the On-premise VP worker.
     * 
     */
    private String configurationDetails;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return Unique name that can be edited. The name should not contain any confidential information.
     * 
     */
    private String displayName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return Geographical information of the On-premise VP worker.
     * 
     */
    private String geoInfo;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitor.
     * 
     */
    private String id;
    /**
     * @return Domain details of the On-premise VP worker.
     * 
     */
    private List<GetOnPremiseVantagePointWorkerIdentityInfo> identityInfos;
    /**
     * @return Monitors list assigned to the On-premise VP worker.
     * 
     */
    private List<GetOnPremiseVantagePointWorkerMonitorList> monitorLists;
    /**
     * @return Unique permanent name of the On-premise VP worker. This is the same as the displayName.
     * 
     */
    private String name;
    private String onPremiseVantagePointId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the On-premise vantage point.
     * 
     */
    private String opvpId;
    /**
     * @return On-premise vantage point name.
     * 
     */
    private String opvpName;
    /**
     * @return Priority of the On-premise VP worker to schedule monitors.
     * 
     */
    private Integer priority;
    private String resourcePrincipalTokenPublicKey;
    /**
     * @return The runtime assigned id of the On-premise VP worker.
     * 
     */
    private String runtimeId;
    /**
     * @return Enables or disables the On-premise VP worker.
     * 
     */
    private String status;
    /**
     * @return The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The time the resource was last synced, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
     * 
     */
    private String timeLastSyncUp;
    /**
     * @return The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
     * 
     */
    private String timeUpdated;
    /**
     * @return Current image version of the On-premise VP worker.
     * 
     */
    private String version;
    /**
     * @return Image version details of the On-premise VP worker.
     * 
     */
    private List<GetOnPremiseVantagePointWorkerVersionDetail> versionDetails;
    private String workerId;
    /**
     * @return Type of the On-premise VP worker.
     * 
     */
    private String workerType;

    private GetOnPremiseVantagePointWorkerResult() {}
    public String apmDomainId() {
        return this.apmDomainId;
    }
    /**
     * @return Configuration details of the On-premise VP worker.
     * 
     */
    public String configurationDetails() {
        return this.configurationDetails;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Unique name that can be edited. The name should not contain any confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return Geographical information of the On-premise VP worker.
     * 
     */
    public String geoInfo() {
        return this.geoInfo;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitor.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Domain details of the On-premise VP worker.
     * 
     */
    public List<GetOnPremiseVantagePointWorkerIdentityInfo> identityInfos() {
        return this.identityInfos;
    }
    /**
     * @return Monitors list assigned to the On-premise VP worker.
     * 
     */
    public List<GetOnPremiseVantagePointWorkerMonitorList> monitorLists() {
        return this.monitorLists;
    }
    /**
     * @return Unique permanent name of the On-premise VP worker. This is the same as the displayName.
     * 
     */
    public String name() {
        return this.name;
    }
    public String onPremiseVantagePointId() {
        return this.onPremiseVantagePointId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the On-premise vantage point.
     * 
     */
    public String opvpId() {
        return this.opvpId;
    }
    /**
     * @return On-premise vantage point name.
     * 
     */
    public String opvpName() {
        return this.opvpName;
    }
    /**
     * @return Priority of the On-premise VP worker to schedule monitors.
     * 
     */
    public Integer priority() {
        return this.priority;
    }
    public String resourcePrincipalTokenPublicKey() {
        return this.resourcePrincipalTokenPublicKey;
    }
    /**
     * @return The runtime assigned id of the On-premise VP worker.
     * 
     */
    public String runtimeId() {
        return this.runtimeId;
    }
    /**
     * @return Enables or disables the On-premise VP worker.
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the resource was last synced, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
     * 
     */
    public String timeLastSyncUp() {
        return this.timeLastSyncUp;
    }
    /**
     * @return The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return Current image version of the On-premise VP worker.
     * 
     */
    public String version() {
        return this.version;
    }
    /**
     * @return Image version details of the On-premise VP worker.
     * 
     */
    public List<GetOnPremiseVantagePointWorkerVersionDetail> versionDetails() {
        return this.versionDetails;
    }
    public String workerId() {
        return this.workerId;
    }
    /**
     * @return Type of the On-premise VP worker.
     * 
     */
    public String workerType() {
        return this.workerType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetOnPremiseVantagePointWorkerResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String apmDomainId;
        private String configurationDetails;
        private Map<String,String> definedTags;
        private String displayName;
        private Map<String,String> freeformTags;
        private String geoInfo;
        private String id;
        private List<GetOnPremiseVantagePointWorkerIdentityInfo> identityInfos;
        private List<GetOnPremiseVantagePointWorkerMonitorList> monitorLists;
        private String name;
        private String onPremiseVantagePointId;
        private String opvpId;
        private String opvpName;
        private Integer priority;
        private String resourcePrincipalTokenPublicKey;
        private String runtimeId;
        private String status;
        private String timeCreated;
        private String timeLastSyncUp;
        private String timeUpdated;
        private String version;
        private List<GetOnPremiseVantagePointWorkerVersionDetail> versionDetails;
        private String workerId;
        private String workerType;
        public Builder() {}
        public Builder(GetOnPremiseVantagePointWorkerResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.apmDomainId = defaults.apmDomainId;
    	      this.configurationDetails = defaults.configurationDetails;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.geoInfo = defaults.geoInfo;
    	      this.id = defaults.id;
    	      this.identityInfos = defaults.identityInfos;
    	      this.monitorLists = defaults.monitorLists;
    	      this.name = defaults.name;
    	      this.onPremiseVantagePointId = defaults.onPremiseVantagePointId;
    	      this.opvpId = defaults.opvpId;
    	      this.opvpName = defaults.opvpName;
    	      this.priority = defaults.priority;
    	      this.resourcePrincipalTokenPublicKey = defaults.resourcePrincipalTokenPublicKey;
    	      this.runtimeId = defaults.runtimeId;
    	      this.status = defaults.status;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeLastSyncUp = defaults.timeLastSyncUp;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.version = defaults.version;
    	      this.versionDetails = defaults.versionDetails;
    	      this.workerId = defaults.workerId;
    	      this.workerType = defaults.workerType;
        }

        @CustomType.Setter
        public Builder apmDomainId(String apmDomainId) {
            if (apmDomainId == null) {
              throw new MissingRequiredPropertyException("GetOnPremiseVantagePointWorkerResult", "apmDomainId");
            }
            this.apmDomainId = apmDomainId;
            return this;
        }
        @CustomType.Setter
        public Builder configurationDetails(String configurationDetails) {
            if (configurationDetails == null) {
              throw new MissingRequiredPropertyException("GetOnPremiseVantagePointWorkerResult", "configurationDetails");
            }
            this.configurationDetails = configurationDetails;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetOnPremiseVantagePointWorkerResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetOnPremiseVantagePointWorkerResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetOnPremiseVantagePointWorkerResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder geoInfo(String geoInfo) {
            if (geoInfo == null) {
              throw new MissingRequiredPropertyException("GetOnPremiseVantagePointWorkerResult", "geoInfo");
            }
            this.geoInfo = geoInfo;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetOnPremiseVantagePointWorkerResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder identityInfos(List<GetOnPremiseVantagePointWorkerIdentityInfo> identityInfos) {
            if (identityInfos == null) {
              throw new MissingRequiredPropertyException("GetOnPremiseVantagePointWorkerResult", "identityInfos");
            }
            this.identityInfos = identityInfos;
            return this;
        }
        public Builder identityInfos(GetOnPremiseVantagePointWorkerIdentityInfo... identityInfos) {
            return identityInfos(List.of(identityInfos));
        }
        @CustomType.Setter
        public Builder monitorLists(List<GetOnPremiseVantagePointWorkerMonitorList> monitorLists) {
            if (monitorLists == null) {
              throw new MissingRequiredPropertyException("GetOnPremiseVantagePointWorkerResult", "monitorLists");
            }
            this.monitorLists = monitorLists;
            return this;
        }
        public Builder monitorLists(GetOnPremiseVantagePointWorkerMonitorList... monitorLists) {
            return monitorLists(List.of(monitorLists));
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetOnPremiseVantagePointWorkerResult", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder onPremiseVantagePointId(String onPremiseVantagePointId) {
            if (onPremiseVantagePointId == null) {
              throw new MissingRequiredPropertyException("GetOnPremiseVantagePointWorkerResult", "onPremiseVantagePointId");
            }
            this.onPremiseVantagePointId = onPremiseVantagePointId;
            return this;
        }
        @CustomType.Setter
        public Builder opvpId(String opvpId) {
            if (opvpId == null) {
              throw new MissingRequiredPropertyException("GetOnPremiseVantagePointWorkerResult", "opvpId");
            }
            this.opvpId = opvpId;
            return this;
        }
        @CustomType.Setter
        public Builder opvpName(String opvpName) {
            if (opvpName == null) {
              throw new MissingRequiredPropertyException("GetOnPremiseVantagePointWorkerResult", "opvpName");
            }
            this.opvpName = opvpName;
            return this;
        }
        @CustomType.Setter
        public Builder priority(Integer priority) {
            if (priority == null) {
              throw new MissingRequiredPropertyException("GetOnPremiseVantagePointWorkerResult", "priority");
            }
            this.priority = priority;
            return this;
        }
        @CustomType.Setter
        public Builder resourcePrincipalTokenPublicKey(String resourcePrincipalTokenPublicKey) {
            if (resourcePrincipalTokenPublicKey == null) {
              throw new MissingRequiredPropertyException("GetOnPremiseVantagePointWorkerResult", "resourcePrincipalTokenPublicKey");
            }
            this.resourcePrincipalTokenPublicKey = resourcePrincipalTokenPublicKey;
            return this;
        }
        @CustomType.Setter
        public Builder runtimeId(String runtimeId) {
            if (runtimeId == null) {
              throw new MissingRequiredPropertyException("GetOnPremiseVantagePointWorkerResult", "runtimeId");
            }
            this.runtimeId = runtimeId;
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            if (status == null) {
              throw new MissingRequiredPropertyException("GetOnPremiseVantagePointWorkerResult", "status");
            }
            this.status = status;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetOnPremiseVantagePointWorkerResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeLastSyncUp(String timeLastSyncUp) {
            if (timeLastSyncUp == null) {
              throw new MissingRequiredPropertyException("GetOnPremiseVantagePointWorkerResult", "timeLastSyncUp");
            }
            this.timeLastSyncUp = timeLastSyncUp;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetOnPremiseVantagePointWorkerResult", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        @CustomType.Setter
        public Builder version(String version) {
            if (version == null) {
              throw new MissingRequiredPropertyException("GetOnPremiseVantagePointWorkerResult", "version");
            }
            this.version = version;
            return this;
        }
        @CustomType.Setter
        public Builder versionDetails(List<GetOnPremiseVantagePointWorkerVersionDetail> versionDetails) {
            if (versionDetails == null) {
              throw new MissingRequiredPropertyException("GetOnPremiseVantagePointWorkerResult", "versionDetails");
            }
            this.versionDetails = versionDetails;
            return this;
        }
        public Builder versionDetails(GetOnPremiseVantagePointWorkerVersionDetail... versionDetails) {
            return versionDetails(List.of(versionDetails));
        }
        @CustomType.Setter
        public Builder workerId(String workerId) {
            if (workerId == null) {
              throw new MissingRequiredPropertyException("GetOnPremiseVantagePointWorkerResult", "workerId");
            }
            this.workerId = workerId;
            return this;
        }
        @CustomType.Setter
        public Builder workerType(String workerType) {
            if (workerType == null) {
              throw new MissingRequiredPropertyException("GetOnPremiseVantagePointWorkerResult", "workerType");
            }
            this.workerType = workerType;
            return this;
        }
        public GetOnPremiseVantagePointWorkerResult build() {
            final var _resultValue = new GetOnPremiseVantagePointWorkerResult();
            _resultValue.apmDomainId = apmDomainId;
            _resultValue.configurationDetails = configurationDetails;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.geoInfo = geoInfo;
            _resultValue.id = id;
            _resultValue.identityInfos = identityInfos;
            _resultValue.monitorLists = monitorLists;
            _resultValue.name = name;
            _resultValue.onPremiseVantagePointId = onPremiseVantagePointId;
            _resultValue.opvpId = opvpId;
            _resultValue.opvpName = opvpName;
            _resultValue.priority = priority;
            _resultValue.resourcePrincipalTokenPublicKey = resourcePrincipalTokenPublicKey;
            _resultValue.runtimeId = runtimeId;
            _resultValue.status = status;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeLastSyncUp = timeLastSyncUp;
            _resultValue.timeUpdated = timeUpdated;
            _resultValue.version = version;
            _resultValue.versionDetails = versionDetails;
            _resultValue.workerId = workerId;
            _resultValue.workerType = workerType;
            return _resultValue;
        }
    }
}
