// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Mysql.outputs.GetMysqlDbSystemsDbSystemChannelSource;
import com.pulumi.oci.Mysql.outputs.GetMysqlDbSystemsDbSystemChannelTarget;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetMysqlDbSystemsDbSystemChannel {
    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return A filter to return only the resource matching the given display name exactly.
     * 
     */
    private String displayName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The OCID of the DB System.
     * 
     */
    private String id;
    /**
     * @return Whether the Channel has been enabled by the user.
     * 
     */
    private Boolean isEnabled;
    /**
     * @return Additional information about the current lifecycleState.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return Parameters detailing how to provision the initial data of the DB System.
     * 
     */
    private List<GetMysqlDbSystemsDbSystemChannelSource> sources;
    /**
     * @return DbSystem Lifecycle State
     * 
     */
    private String state;
    /**
     * @return Details about the Channel target.
     * 
     */
    private List<GetMysqlDbSystemsDbSystemChannelTarget> targets;
    /**
     * @return The date and time the DB System was created.
     * 
     */
    private String timeCreated;
    /**
     * @return The time the DB System was last updated.
     * 
     */
    private String timeUpdated;

    private GetMysqlDbSystemsDbSystemChannel() {}
    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A filter to return only the resource matching the given display name exactly.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of the DB System.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Whether the Channel has been enabled by the user.
     * 
     */
    public Boolean isEnabled() {
        return this.isEnabled;
    }
    /**
     * @return Additional information about the current lifecycleState.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return Parameters detailing how to provision the initial data of the DB System.
     * 
     */
    public List<GetMysqlDbSystemsDbSystemChannelSource> sources() {
        return this.sources;
    }
    /**
     * @return DbSystem Lifecycle State
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Details about the Channel target.
     * 
     */
    public List<GetMysqlDbSystemsDbSystemChannelTarget> targets() {
        return this.targets;
    }
    /**
     * @return The date and time the DB System was created.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the DB System was last updated.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMysqlDbSystemsDbSystemChannel defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private Boolean isEnabled;
        private String lifecycleDetails;
        private List<GetMysqlDbSystemsDbSystemChannelSource> sources;
        private String state;
        private List<GetMysqlDbSystemsDbSystemChannelTarget> targets;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetMysqlDbSystemsDbSystemChannel defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isEnabled = defaults.isEnabled;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.sources = defaults.sources;
    	      this.state = defaults.state;
    	      this.targets = defaults.targets;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder isEnabled(Boolean isEnabled) {
            this.isEnabled = Objects.requireNonNull(isEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        @CustomType.Setter
        public Builder sources(List<GetMysqlDbSystemsDbSystemChannelSource> sources) {
            this.sources = Objects.requireNonNull(sources);
            return this;
        }
        public Builder sources(GetMysqlDbSystemsDbSystemChannelSource... sources) {
            return sources(List.of(sources));
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder targets(List<GetMysqlDbSystemsDbSystemChannelTarget> targets) {
            this.targets = Objects.requireNonNull(targets);
            return this;
        }
        public Builder targets(GetMysqlDbSystemsDbSystemChannelTarget... targets) {
            return targets(List.of(targets));
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        public GetMysqlDbSystemsDbSystemChannel build() {
            final var o = new GetMysqlDbSystemsDbSystemChannel();
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.id = id;
            o.isEnabled = isEnabled;
            o.lifecycleDetails = lifecycleDetails;
            o.sources = sources;
            o.state = state;
            o.targets = targets;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            return o;
        }
    }
}