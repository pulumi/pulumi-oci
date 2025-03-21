// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsDynamicResourceGroupUrnietfparamsscimschemasoracleidcsextensionOciTagDefinedTag {
    /**
     * @return Oracle Cloud Infrastructure Tag key
     * 
     */
    private String key;
    /**
     * @return Oracle Cloud Infrastructure Tag namespace
     * 
     */
    private String namespace;
    /**
     * @return Oracle Cloud Infrastructure Tag value
     * 
     */
    private String value;

    private GetDomainsDynamicResourceGroupUrnietfparamsscimschemasoracleidcsextensionOciTagDefinedTag() {}
    /**
     * @return Oracle Cloud Infrastructure Tag key
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return Oracle Cloud Infrastructure Tag namespace
     * 
     */
    public String namespace() {
        return this.namespace;
    }
    /**
     * @return Oracle Cloud Infrastructure Tag value
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsDynamicResourceGroupUrnietfparamsscimschemasoracleidcsextensionOciTagDefinedTag defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String key;
        private String namespace;
        private String value;
        public Builder() {}
        public Builder(GetDomainsDynamicResourceGroupUrnietfparamsscimschemasoracleidcsextensionOciTagDefinedTag defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.key = defaults.key;
    	      this.namespace = defaults.namespace;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder key(String key) {
            if (key == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupUrnietfparamsscimschemasoracleidcsextensionOciTagDefinedTag", "key");
            }
            this.key = key;
            return this;
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            if (namespace == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupUrnietfparamsscimschemasoracleidcsextensionOciTagDefinedTag", "namespace");
            }
            this.namespace = namespace;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("GetDomainsDynamicResourceGroupUrnietfparamsscimschemasoracleidcsextensionOciTagDefinedTag", "value");
            }
            this.value = value;
            return this;
        }
        public GetDomainsDynamicResourceGroupUrnietfparamsscimschemasoracleidcsextensionOciTagDefinedTag build() {
            final var _resultValue = new GetDomainsDynamicResourceGroupUrnietfparamsscimschemasoracleidcsextensionOciTagDefinedTag();
            _resultValue.key = key;
            _resultValue.namespace = namespace;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
