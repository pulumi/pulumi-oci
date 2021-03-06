// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetTagDefaultsTagDefault {
    /**
     * @return The OCID of the compartment (remember that the tenancy is simply the root compartment).
     * 
     */
    private final String compartmentId;
    /**
     * @return A filter to only return resources that match the specified OCID exactly.
     * 
     */
    private final String id;
    /**
     * @return If you specify that a value is required, a value is set during resource creation (either by the user creating the resource or another tag defualt). If no value is set, resource creation is blocked.
     * * If the `isRequired` flag is set to &#34;true&#34;, the value is set during resource creation.
     * * If the `isRequired` flag is set to &#34;false&#34;, the value you enter is set during resource creation.
     * 
     */
    private final Boolean isRequired;
    /**
     * @return A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     * 
     */
    private final String state;
    /**
     * @return The OCID of the tag definition.
     * 
     */
    private final String tagDefinitionId;
    /**
     * @return The name used in the tag definition. This field is informational in the context of the tag default.
     * 
     */
    private final String tagDefinitionName;
    /**
     * @return The OCID of the tag namespace that contains the tag definition.
     * 
     */
    private final String tagNamespaceId;
    /**
     * @return Date and time the `TagDefault` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private final String timeCreated;
    /**
     * @return The default value for the tag definition. This will be applied to all new resources created in the compartment.
     * 
     */
    private final String value;

    @CustomType.Constructor
    private GetTagDefaultsTagDefault(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("isRequired") Boolean isRequired,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("tagDefinitionId") String tagDefinitionId,
        @CustomType.Parameter("tagDefinitionName") String tagDefinitionName,
        @CustomType.Parameter("tagNamespaceId") String tagNamespaceId,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("value") String value) {
        this.compartmentId = compartmentId;
        this.id = id;
        this.isRequired = isRequired;
        this.state = state;
        this.tagDefinitionId = tagDefinitionId;
        this.tagDefinitionName = tagDefinitionName;
        this.tagNamespaceId = tagNamespaceId;
        this.timeCreated = timeCreated;
        this.value = value;
    }

    /**
     * @return The OCID of the compartment (remember that the tenancy is simply the root compartment).
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A filter to only return resources that match the specified OCID exactly.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return If you specify that a value is required, a value is set during resource creation (either by the user creating the resource or another tag defualt). If no value is set, resource creation is blocked.
     * * If the `isRequired` flag is set to &#34;true&#34;, the value is set during resource creation.
     * * If the `isRequired` flag is set to &#34;false&#34;, the value you enter is set during resource creation.
     * 
     */
    public Boolean isRequired() {
        return this.isRequired;
    }
    /**
     * @return A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The OCID of the tag definition.
     * 
     */
    public String tagDefinitionId() {
        return this.tagDefinitionId;
    }
    /**
     * @return The name used in the tag definition. This field is informational in the context of the tag default.
     * 
     */
    public String tagDefinitionName() {
        return this.tagDefinitionName;
    }
    /**
     * @return The OCID of the tag namespace that contains the tag definition.
     * 
     */
    public String tagNamespaceId() {
        return this.tagNamespaceId;
    }
    /**
     * @return Date and time the `TagDefault` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The default value for the tag definition. This will be applied to all new resources created in the compartment.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetTagDefaultsTagDefault defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private String id;
        private Boolean isRequired;
        private String state;
        private String tagDefinitionId;
        private String tagDefinitionName;
        private String tagNamespaceId;
        private String timeCreated;
        private String value;

        public Builder() {
    	      // Empty
        }

        public Builder(GetTagDefaultsTagDefault defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.id = defaults.id;
    	      this.isRequired = defaults.isRequired;
    	      this.state = defaults.state;
    	      this.tagDefinitionId = defaults.tagDefinitionId;
    	      this.tagDefinitionName = defaults.tagDefinitionName;
    	      this.tagNamespaceId = defaults.tagNamespaceId;
    	      this.timeCreated = defaults.timeCreated;
    	      this.value = defaults.value;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder isRequired(Boolean isRequired) {
            this.isRequired = Objects.requireNonNull(isRequired);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder tagDefinitionId(String tagDefinitionId) {
            this.tagDefinitionId = Objects.requireNonNull(tagDefinitionId);
            return this;
        }
        public Builder tagDefinitionName(String tagDefinitionName) {
            this.tagDefinitionName = Objects.requireNonNull(tagDefinitionName);
            return this;
        }
        public Builder tagNamespaceId(String tagNamespaceId) {
            this.tagNamespaceId = Objects.requireNonNull(tagNamespaceId);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder value(String value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }        public GetTagDefaultsTagDefault build() {
            return new GetTagDefaultsTagDefault(compartmentId, id, isRequired, state, tagDefinitionId, tagDefinitionName, tagNamespaceId, timeCreated, value);
        }
    }
}
