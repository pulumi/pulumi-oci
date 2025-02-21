// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Functions.outputs.GetPbfListingVersionsPbfListingVersionsCollectionItemConfig;
import com.pulumi.oci.Functions.outputs.GetPbfListingVersionsPbfListingVersionsCollectionItemRequirement;
import com.pulumi.oci.Functions.outputs.GetPbfListingVersionsPbfListingVersionsCollectionItemTrigger;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetPbfListingVersionsPbfListingVersionsCollectionItem {
    /**
     * @return Details changes are included in this version.
     * 
     */
    private String changeSummary;
    /**
     * @return Details about the required and optional Function configurations needed for proper performance of the PBF.
     * 
     */
    private List<GetPbfListingVersionsPbfListingVersionsCollectionItemConfig> configs;
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
     * @return Unique identifier that is immutable on creation
     * 
     */
    private String id;
    /**
     * @return Matches a PbfListingVersion based on a provided semantic version name for a PbfListingVersion.  Each PbfListingVersion name is unique with respect to its associated PbfListing.
     * 
     */
    private String name;
    /**
     * @return unique PbfListing identifier
     * 
     */
    private String pbfListingId;
    /**
     * @return Minimum memory required by this PBF. The user should use memory greater than or equal to this value  while configuring the Function.
     * 
     */
    private List<GetPbfListingVersionsPbfListingVersionsCollectionItemRequirement> requirements;
    /**
     * @return A filter to return only resources their lifecycleState matches the given lifecycleState.
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
    private List<GetPbfListingVersionsPbfListingVersionsCollectionItemTrigger> triggers;

    private GetPbfListingVersionsPbfListingVersionsCollectionItem() {}
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
    public List<GetPbfListingVersionsPbfListingVersionsCollectionItemConfig> configs() {
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
     * @return Unique identifier that is immutable on creation
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Matches a PbfListingVersion based on a provided semantic version name for a PbfListingVersion.  Each PbfListingVersion name is unique with respect to its associated PbfListing.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return unique PbfListing identifier
     * 
     */
    public String pbfListingId() {
        return this.pbfListingId;
    }
    /**
     * @return Minimum memory required by this PBF. The user should use memory greater than or equal to this value  while configuring the Function.
     * 
     */
    public List<GetPbfListingVersionsPbfListingVersionsCollectionItemRequirement> requirements() {
        return this.requirements;
    }
    /**
     * @return A filter to return only resources their lifecycleState matches the given lifecycleState.
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
    public List<GetPbfListingVersionsPbfListingVersionsCollectionItemTrigger> triggers() {
        return this.triggers;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPbfListingVersionsPbfListingVersionsCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String changeSummary;
        private List<GetPbfListingVersionsPbfListingVersionsCollectionItemConfig> configs;
        private Map<String,String> definedTags;
        private Map<String,String> freeformTags;
        private String id;
        private String name;
        private String pbfListingId;
        private List<GetPbfListingVersionsPbfListingVersionsCollectionItemRequirement> requirements;
        private String state;
        private Map<String,String> systemTags;
        private String timeCreated;
        private String timeUpdated;
        private List<GetPbfListingVersionsPbfListingVersionsCollectionItemTrigger> triggers;
        public Builder() {}
        public Builder(GetPbfListingVersionsPbfListingVersionsCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.changeSummary = defaults.changeSummary;
    	      this.configs = defaults.configs;
    	      this.definedTags = defaults.definedTags;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.name = defaults.name;
    	      this.pbfListingId = defaults.pbfListingId;
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
              throw new MissingRequiredPropertyException("GetPbfListingVersionsPbfListingVersionsCollectionItem", "changeSummary");
            }
            this.changeSummary = changeSummary;
            return this;
        }
        @CustomType.Setter
        public Builder configs(List<GetPbfListingVersionsPbfListingVersionsCollectionItemConfig> configs) {
            if (configs == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionsPbfListingVersionsCollectionItem", "configs");
            }
            this.configs = configs;
            return this;
        }
        public Builder configs(GetPbfListingVersionsPbfListingVersionsCollectionItemConfig... configs) {
            return configs(List.of(configs));
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionsPbfListingVersionsCollectionItem", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionsPbfListingVersionsCollectionItem", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionsPbfListingVersionsCollectionItem", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionsPbfListingVersionsCollectionItem", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder pbfListingId(String pbfListingId) {
            if (pbfListingId == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionsPbfListingVersionsCollectionItem", "pbfListingId");
            }
            this.pbfListingId = pbfListingId;
            return this;
        }
        @CustomType.Setter
        public Builder requirements(List<GetPbfListingVersionsPbfListingVersionsCollectionItemRequirement> requirements) {
            if (requirements == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionsPbfListingVersionsCollectionItem", "requirements");
            }
            this.requirements = requirements;
            return this;
        }
        public Builder requirements(GetPbfListingVersionsPbfListingVersionsCollectionItemRequirement... requirements) {
            return requirements(List.of(requirements));
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionsPbfListingVersionsCollectionItem", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionsPbfListingVersionsCollectionItem", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionsPbfListingVersionsCollectionItem", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionsPbfListingVersionsCollectionItem", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        @CustomType.Setter
        public Builder triggers(List<GetPbfListingVersionsPbfListingVersionsCollectionItemTrigger> triggers) {
            if (triggers == null) {
              throw new MissingRequiredPropertyException("GetPbfListingVersionsPbfListingVersionsCollectionItem", "triggers");
            }
            this.triggers = triggers;
            return this;
        }
        public Builder triggers(GetPbfListingVersionsPbfListingVersionsCollectionItemTrigger... triggers) {
            return triggers(List.of(triggers));
        }
        public GetPbfListingVersionsPbfListingVersionsCollectionItem build() {
            final var _resultValue = new GetPbfListingVersionsPbfListingVersionsCollectionItem();
            _resultValue.changeSummary = changeSummary;
            _resultValue.configs = configs;
            _resultValue.definedTags = definedTags;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.name = name;
            _resultValue.pbfListingId = pbfListingId;
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
