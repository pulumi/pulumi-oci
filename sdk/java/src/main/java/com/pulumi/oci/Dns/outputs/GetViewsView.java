// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetViewsView {
    /**
     * @return The OCID of the compartment the resource belongs to.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return The displayName of a resource.
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The OCID of a resource.
     * 
     */
    private String id;
    /**
     * @return A Boolean flag indicating whether or not parts of the resource are unable to be explicitly managed.
     * 
     */
    private Boolean isProtected;
    /**
     * @return Value must be `PRIVATE` when listing private views.
     * 
     */
    private String scope;
    /**
     * @return The canonical absolute URL of the resource.
     * 
     */
    private String self;
    /**
     * @return The state of a resource.
     * 
     */
    private String state;
    /**
     * @return The date and time the resource was created in &#34;YYYY-MM-ddThh:mm:ssZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the resource was last updated in &#34;YYYY-MM-ddThh:mm:ssZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    private String timeUpdated;

    private GetViewsView() {}
    /**
     * @return The OCID of the compartment the resource belongs to.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The displayName of a resource.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of a resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A Boolean flag indicating whether or not parts of the resource are unable to be explicitly managed.
     * 
     */
    public Boolean isProtected() {
        return this.isProtected;
    }
    /**
     * @return Value must be `PRIVATE` when listing private views.
     * 
     */
    public String scope() {
        return this.scope;
    }
    /**
     * @return The canonical absolute URL of the resource.
     * 
     */
    public String self() {
        return this.self;
    }
    /**
     * @return The state of a resource.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the resource was created in &#34;YYYY-MM-ddThh:mm:ssZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the resource was last updated in &#34;YYYY-MM-ddThh:mm:ssZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetViewsView defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private Boolean isProtected;
        private String scope;
        private String self;
        private String state;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetViewsView defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isProtected = defaults.isProtected;
    	      this.scope = defaults.scope;
    	      this.self = defaults.self;
    	      this.state = defaults.state;
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
        public Builder isProtected(Boolean isProtected) {
            this.isProtected = Objects.requireNonNull(isProtected);
            return this;
        }
        @CustomType.Setter
        public Builder scope(String scope) {
            this.scope = Objects.requireNonNull(scope);
            return this;
        }
        @CustomType.Setter
        public Builder self(String self) {
            this.self = Objects.requireNonNull(self);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
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
        public GetViewsView build() {
            final var o = new GetViewsView();
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.id = id;
            o.isProtected = isProtected;
            o.scope = scope;
            o.self = self;
            o.state = state;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            return o;
        }
    }
}