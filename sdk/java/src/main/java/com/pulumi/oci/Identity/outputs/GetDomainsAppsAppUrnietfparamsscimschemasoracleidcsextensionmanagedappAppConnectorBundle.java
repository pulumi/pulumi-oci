// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppConnectorBundle {
    /**
     * @return Display-name of the AppRole.
     * 
     */
    private String display;
    /**
     * @return URI of the AppRole.
     * 
     */
    private String ref;
    /**
     * @return Object Class type. Allowed values are AccountObjectClass, ManagedObjectClass.
     * 
     */
    private String type;
    /**
     * @return ID of the AppRole.
     * 
     */
    private String value;
    /**
     * @return Unique well-known identifier used to reference connector bundle.
     * 
     */
    private String wellKnownId;

    private GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppConnectorBundle() {}
    /**
     * @return Display-name of the AppRole.
     * 
     */
    public String display() {
        return this.display;
    }
    /**
     * @return URI of the AppRole.
     * 
     */
    public String ref() {
        return this.ref;
    }
    /**
     * @return Object Class type. Allowed values are AccountObjectClass, ManagedObjectClass.
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return ID of the AppRole.
     * 
     */
    public String value() {
        return this.value;
    }
    /**
     * @return Unique well-known identifier used to reference connector bundle.
     * 
     */
    public String wellKnownId() {
        return this.wellKnownId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppConnectorBundle defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String display;
        private String ref;
        private String type;
        private String value;
        private String wellKnownId;
        public Builder() {}
        public Builder(GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppConnectorBundle defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.display = defaults.display;
    	      this.ref = defaults.ref;
    	      this.type = defaults.type;
    	      this.value = defaults.value;
    	      this.wellKnownId = defaults.wellKnownId;
        }

        @CustomType.Setter
        public Builder display(String display) {
            if (display == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppConnectorBundle", "display");
            }
            this.display = display;
            return this;
        }
        @CustomType.Setter
        public Builder ref(String ref) {
            if (ref == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppConnectorBundle", "ref");
            }
            this.ref = ref;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppConnectorBundle", "type");
            }
            this.type = type;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppConnectorBundle", "value");
            }
            this.value = value;
            return this;
        }
        @CustomType.Setter
        public Builder wellKnownId(String wellKnownId) {
            if (wellKnownId == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppConnectorBundle", "wellKnownId");
            }
            this.wellKnownId = wellKnownId;
            return this;
        }
        public GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppConnectorBundle build() {
            final var _resultValue = new GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppConnectorBundle();
            _resultValue.display = display;
            _resultValue.ref = ref;
            _resultValue.type = type;
            _resultValue.value = value;
            _resultValue.wellKnownId = wellKnownId;
            return _resultValue;
        }
    }
}
