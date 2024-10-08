// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Dns.outputs.GetResolverAttachedView;
import com.pulumi.oci.Dns.outputs.GetResolverEndpoint;
import com.pulumi.oci.Dns.outputs.GetResolverRule;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetResolverResult {
    /**
     * @return The OCID of the attached VCN.
     * 
     */
    private String attachedVcnId;
    /**
     * @return The attached views. Views are evaluated in order.
     * 
     */
    private List<GetResolverAttachedView> attachedViews;
    /**
     * @return The OCID of the owning compartment. This will match the resolver that the resolver endpoint is under and will be updated if the resolver&#39;s compartment is changed.
     * 
     */
    private String compartmentId;
    /**
     * @return The OCID of the default view.
     * 
     */
    private String defaultViewId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return The display name of the resolver.
     * 
     */
    private String displayName;
    /**
     * @return Read-only array of endpoints for the resolver.
     * 
     */
    private List<GetResolverEndpoint> endpoints;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The OCID of the resolver.
     * 
     */
    private String id;
    /**
     * @return A Boolean flag indicating whether or not parts of the resource are unable to be explicitly managed.
     * 
     */
    private Boolean isProtected;
    private String resolverId;
    /**
     * @return Rules for the resolver. Rules are evaluated in order.
     * 
     */
    private List<GetResolverRule> rules;
    private @Nullable String scope;
    /**
     * @return The canonical absolute URL of the resource.
     * 
     */
    private String self;
    /**
     * @return The current state of the resource.
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

    private GetResolverResult() {}
    /**
     * @return The OCID of the attached VCN.
     * 
     */
    public String attachedVcnId() {
        return this.attachedVcnId;
    }
    /**
     * @return The attached views. Views are evaluated in order.
     * 
     */
    public List<GetResolverAttachedView> attachedViews() {
        return this.attachedViews;
    }
    /**
     * @return The OCID of the owning compartment. This will match the resolver that the resolver endpoint is under and will be updated if the resolver&#39;s compartment is changed.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The OCID of the default view.
     * 
     */
    public String defaultViewId() {
        return this.defaultViewId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The display name of the resolver.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Read-only array of endpoints for the resolver.
     * 
     */
    public List<GetResolverEndpoint> endpoints() {
        return this.endpoints;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of the resolver.
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
    public String resolverId() {
        return this.resolverId;
    }
    /**
     * @return Rules for the resolver. Rules are evaluated in order.
     * 
     */
    public List<GetResolverRule> rules() {
        return this.rules;
    }
    public Optional<String> scope() {
        return Optional.ofNullable(this.scope);
    }
    /**
     * @return The canonical absolute URL of the resource.
     * 
     */
    public String self() {
        return this.self;
    }
    /**
     * @return The current state of the resource.
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

    public static Builder builder(GetResolverResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String attachedVcnId;
        private List<GetResolverAttachedView> attachedViews;
        private String compartmentId;
        private String defaultViewId;
        private Map<String,String> definedTags;
        private String displayName;
        private List<GetResolverEndpoint> endpoints;
        private Map<String,String> freeformTags;
        private String id;
        private Boolean isProtected;
        private String resolverId;
        private List<GetResolverRule> rules;
        private @Nullable String scope;
        private String self;
        private String state;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetResolverResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.attachedVcnId = defaults.attachedVcnId;
    	      this.attachedViews = defaults.attachedViews;
    	      this.compartmentId = defaults.compartmentId;
    	      this.defaultViewId = defaults.defaultViewId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.endpoints = defaults.endpoints;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isProtected = defaults.isProtected;
    	      this.resolverId = defaults.resolverId;
    	      this.rules = defaults.rules;
    	      this.scope = defaults.scope;
    	      this.self = defaults.self;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder attachedVcnId(String attachedVcnId) {
            if (attachedVcnId == null) {
              throw new MissingRequiredPropertyException("GetResolverResult", "attachedVcnId");
            }
            this.attachedVcnId = attachedVcnId;
            return this;
        }
        @CustomType.Setter
        public Builder attachedViews(List<GetResolverAttachedView> attachedViews) {
            if (attachedViews == null) {
              throw new MissingRequiredPropertyException("GetResolverResult", "attachedViews");
            }
            this.attachedViews = attachedViews;
            return this;
        }
        public Builder attachedViews(GetResolverAttachedView... attachedViews) {
            return attachedViews(List.of(attachedViews));
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetResolverResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder defaultViewId(String defaultViewId) {
            if (defaultViewId == null) {
              throw new MissingRequiredPropertyException("GetResolverResult", "defaultViewId");
            }
            this.defaultViewId = defaultViewId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetResolverResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetResolverResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder endpoints(List<GetResolverEndpoint> endpoints) {
            if (endpoints == null) {
              throw new MissingRequiredPropertyException("GetResolverResult", "endpoints");
            }
            this.endpoints = endpoints;
            return this;
        }
        public Builder endpoints(GetResolverEndpoint... endpoints) {
            return endpoints(List.of(endpoints));
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetResolverResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetResolverResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isProtected(Boolean isProtected) {
            if (isProtected == null) {
              throw new MissingRequiredPropertyException("GetResolverResult", "isProtected");
            }
            this.isProtected = isProtected;
            return this;
        }
        @CustomType.Setter
        public Builder resolverId(String resolverId) {
            if (resolverId == null) {
              throw new MissingRequiredPropertyException("GetResolverResult", "resolverId");
            }
            this.resolverId = resolverId;
            return this;
        }
        @CustomType.Setter
        public Builder rules(List<GetResolverRule> rules) {
            if (rules == null) {
              throw new MissingRequiredPropertyException("GetResolverResult", "rules");
            }
            this.rules = rules;
            return this;
        }
        public Builder rules(GetResolverRule... rules) {
            return rules(List.of(rules));
        }
        @CustomType.Setter
        public Builder scope(@Nullable String scope) {

            this.scope = scope;
            return this;
        }
        @CustomType.Setter
        public Builder self(String self) {
            if (self == null) {
              throw new MissingRequiredPropertyException("GetResolverResult", "self");
            }
            this.self = self;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetResolverResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetResolverResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetResolverResult", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetResolverResult build() {
            final var _resultValue = new GetResolverResult();
            _resultValue.attachedVcnId = attachedVcnId;
            _resultValue.attachedViews = attachedViews;
            _resultValue.compartmentId = compartmentId;
            _resultValue.defaultViewId = defaultViewId;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.endpoints = endpoints;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.isProtected = isProtected;
            _resultValue.resolverId = resolverId;
            _resultValue.rules = rules;
            _resultValue.scope = scope;
            _resultValue.self = self;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
