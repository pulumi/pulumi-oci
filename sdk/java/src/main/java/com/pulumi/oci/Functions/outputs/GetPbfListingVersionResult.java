// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Functions.outputs.GetPbfListingVersionConfig;
import com.pulumi.oci.Functions.outputs.GetPbfListingVersionRequirement;
import com.pulumi.oci.Functions.outputs.GetPbfListingVersionTrigger;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetPbfListingVersionResult {
    /**
     * @return Details changes are included in this version.
     * 
     */
    private String changeSummary;
    /**
     * @return Details about the required and optional Function configurations needed for proper performance of the PBF.
     * 
     */
    private List<GetPbfListingVersionConfig> configs;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return A brief descriptive name for the PBF trigger.
     * 
     */
    private String name;
    /**
     * @return The OCID of the PbfListing this resource version belongs to.
     * 
     */
    private String pbfListingId;
    private String pbfListingVersionId;
    /**
     * @return Minimum memory required by this PBF. The user should use memory greater than or equal to this value  while configuring the Function.
     * 
     */
    private List<GetPbfListingVersionRequirement> requirements;
    /**
     * @return The current state of the PBF resource.
     * 
     */
    private String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return The time the PbfListingVersion was created. An RFC3339 formatted datetime string.
     * 
     */
    private String timeCreated;
    /**
     * @return The last time the PbfListingVersion was updated. An RFC3339 formatted datetime string.
     * 
     */
    private String timeUpdated;
    /**
     * @return An array of Trigger. A list of triggers that may activate the PBF.
     * 
     */
    private List<GetPbfListingVersionTrigger> triggers;

    private GetPbfListingVersionResult() {}
    /**
     * @return Details changes are included in this version.
     * 
     */
    public String changeSummary() {
        return this.changeSummary;
    }
    /**
     * @return Details about the required and optional Function configurations needed for proper performance of the PBF.
     * 
     */
    public List<GetPbfListingVersionConfig> configs() {
        return this.configs;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A brief descriptive name for the PBF trigger.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The OCID of the PbfListing this resource version belongs to.
     * 
     */
    public String pbfListingId() {
        return this.pbfListingId;
    }
    public String pbfListingVersionId() {
        return this.pbfListingVersionId;
    }
    /**
     * @return Minimum memory required by this PBF. The user should use memory greater than or equal to this value  while configuring the Function.
     * 
     */
    public List<GetPbfListingVersionRequirement> requirements() {
        return this.requirements;
    }
    /**
     * @return The current state of the PBF resource.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The time the PbfListingVersion was created. An RFC3339 formatted datetime string.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The last time the PbfListingVersion was updated. An RFC3339 formatted datetime string.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return An array of Trigger. A list of triggers that may activate the PBF.
     * 
     */
    public List<GetPbfListingVersionTrigger> triggers() {
        return this.triggers;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPbfListingVersionResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String changeSummary;
        private List<GetPbfListingVersionConfig> configs;
        private Map<String,String> definedTags;
        private Map<String,String> freeformTags;
        private String id;
        private String name;
        private String pbfListingId;
        private String pbfListingVersionId;
        private List<GetPbfListingVersionRequirement> requirements;
        private String state;
        private Map<String,String> systemTags;
        private String timeCreated;
        private String timeUpdated;
        private List<GetPbfListingVersionTrigger> triggers;
        public Builder() {}
        public Builder(GetPbfListingVersionResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.changeSummary = defaults.changeSummary;
    	      this.configs = defaults.configs;
    	      this.definedTags = defaults.definedTags;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.name = defaults.name;
    	      this.pbfListingId = defaults.pbfListingId;
    	      this.pbfListingVersionId = defaults.pbfListingVersionId;
    	      this.requirements = defaults.requirements;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.triggers = defaults.triggers;
        }

        @CustomType.Setter
        public Builder changeSummary(String changeSummary) {
            if (changeSummary == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionResult", "changeSummary");
            }
            this.changeSummary = changeSummary;
            return this;
        }
        @CustomType.Setter
        public Builder configs(List<GetPbfListingVersionConfig> configs) {
            if (configs == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionResult", "configs");
            }
            this.configs = configs;
            return this;
        }
        public Builder configs(GetPbfListingVersionConfig... configs) {
            return configs(List.of(configs));
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionResult", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder pbfListingId(String pbfListingId) {
            if (pbfListingId == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionResult", "pbfListingId");
            }
            this.pbfListingId = pbfListingId;
            return this;
        }
        @CustomType.Setter
        public Builder pbfListingVersionId(String pbfListingVersionId) {
            if (pbfListingVersionId == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionResult", "pbfListingVersionId");
            }
            this.pbfListingVersionId = pbfListingVersionId;
            return this;
        }
        @CustomType.Setter
        public Builder requirements(List<GetPbfListingVersionRequirement> requirements) {
            if (requirements == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionResult", "requirements");
            }
            this.requirements = requirements;
            return this;
        }
        public Builder requirements(GetPbfListingVersionRequirement... requirements) {
            return requirements(List.of(requirements));
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionResult", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionResult", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        @CustomType.Setter
        public Builder triggers(List<GetPbfListingVersionTrigger> triggers) {
            if (triggers == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionResult", "triggers");
            }
            this.triggers = triggers;
            return this;
        }
        public Builder triggers(GetPbfListingVersionTrigger... triggers) {
            return triggers(List.of(triggers));
        }
        public GetPbfListingVersionResult build() {
            final var _resultValue = new GetPbfListingVersionResult();
            _resultValue.changeSummary = changeSummary;
            _resultValue.configs = configs;
            _resultValue.definedTags = definedTags;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.name = name;
            _resultValue.pbfListingId = pbfListingId;
            _resultValue.pbfListingVersionId = pbfListingVersionId;
            _resultValue.requirements = requirements;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            _resultValue.triggers = triggers;
            return _resultValue;
        }
    }
}
