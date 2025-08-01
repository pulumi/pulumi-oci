// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetConnectionsConnectionCollectionItemAdditionalAttribute {
    /**
     * @return The catalog name within Polaris where Iceberg tables are registered.
     * 
     */
    private String name;
    /**
     * @return The value of the property entry.
     * 
     */
    private String value;

    private GetConnectionsConnectionCollectionItemAdditionalAttribute() {}
    /**
     * @return The catalog name within Polaris where Iceberg tables are registered.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The value of the property entry.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetConnectionsConnectionCollectionItemAdditionalAttribute defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        private String value;
        public Builder() {}
        public Builder(GetConnectionsConnectionCollectionItemAdditionalAttribute defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetConnectionsConnectionCollectionItemAdditionalAttribute", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("GetConnectionsConnectionCollectionItemAdditionalAttribute", "value");
            }
            this.value = value;
            return this;
        }
        public GetConnectionsConnectionCollectionItemAdditionalAttribute build() {
            final var _resultValue = new GetConnectionsConnectionCollectionItemAdditionalAttribute();
            _resultValue.name = name;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
