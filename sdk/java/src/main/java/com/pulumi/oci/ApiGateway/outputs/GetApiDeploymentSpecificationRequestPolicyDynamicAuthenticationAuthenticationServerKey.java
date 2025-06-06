// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetApiDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerKey {
    /**
     * @return String describing the expression with wildcards.
     * 
     */
    private String expression;
    /**
     * @return Information regarding whether this is the default branch.
     * 
     */
    private Boolean isDefault;
    /**
     * @return The case-insensitive name of the header.  This name must be unique across transformation policies.
     * 
     */
    private String name;
    /**
     * @return Type of the Response Cache Store Policy.
     * 
     */
    private String type;
    /**
     * @return A list of new values.  Each value can be a constant or may include one or more expressions enclosed within ${} delimiters.
     * 
     */
    private List<String> values;

    private GetApiDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerKey() {}
    /**
     * @return String describing the expression with wildcards.
     * 
     */
    public String expression() {
        return this.expression;
    }
    /**
     * @return Information regarding whether this is the default branch.
     * 
     */
    public Boolean isDefault() {
        return this.isDefault;
    }
    /**
     * @return The case-insensitive name of the header.  This name must be unique across transformation policies.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Type of the Response Cache Store Policy.
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return A list of new values.  Each value can be a constant or may include one or more expressions enclosed within ${} delimiters.
     * 
     */
    public List<String> values() {
        return this.values;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetApiDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerKey defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String expression;
        private Boolean isDefault;
        private String name;
        private String type;
        private List<String> values;
        public Builder() {}
        public Builder(GetApiDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerKey defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.expression = defaults.expression;
    	      this.isDefault = defaults.isDefault;
    	      this.name = defaults.name;
    	      this.type = defaults.type;
    	      this.values = defaults.values;
        }

        @CustomType.Setter
        public Builder expression(String expression) {
            if (expression == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerKey", "expression");
            }
            this.expression = expression;
            return this;
        }
        @CustomType.Setter
        public Builder isDefault(Boolean isDefault) {
            if (isDefault == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerKey", "isDefault");
            }
            this.isDefault = isDefault;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerKey", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerKey", "type");
            }
            this.type = type;
            return this;
        }
        @CustomType.Setter
        public Builder values(List<String> values) {
            if (values == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerKey", "values");
            }
            this.values = values;
            return this;
        }
        public Builder values(String... values) {
            return values(List.of(values));
        }
        public GetApiDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerKey build() {
            final var _resultValue = new GetApiDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerKey();
            _resultValue.expression = expression;
            _resultValue.isDefault = isDefault;
            _resultValue.name = name;
            _resultValue.type = type;
            _resultValue.values = values;
            return _resultValue;
        }
    }
}
