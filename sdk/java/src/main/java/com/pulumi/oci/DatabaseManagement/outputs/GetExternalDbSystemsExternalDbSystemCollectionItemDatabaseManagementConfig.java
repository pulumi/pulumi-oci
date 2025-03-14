// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetExternalDbSystemsExternalDbSystemCollectionItemDatabaseManagementConfig {
    /**
     * @return The Oracle license model that applies to the external database.
     * 
     */
    private String licenseModel;

    private GetExternalDbSystemsExternalDbSystemCollectionItemDatabaseManagementConfig() {}
    /**
     * @return The Oracle license model that applies to the external database.
     * 
     */
    public String licenseModel() {
        return this.licenseModel;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExternalDbSystemsExternalDbSystemCollectionItemDatabaseManagementConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String licenseModel;
        public Builder() {}
        public Builder(GetExternalDbSystemsExternalDbSystemCollectionItemDatabaseManagementConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.licenseModel = defaults.licenseModel;
        }

        @CustomType.Setter
        public Builder licenseModel(String licenseModel) {
            if (licenseModel == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemsExternalDbSystemCollectionItemDatabaseManagementConfig", "licenseModel");
            }
            this.licenseModel = licenseModel;
            return this;
        }
        public GetExternalDbSystemsExternalDbSystemCollectionItemDatabaseManagementConfig build() {
            final var _resultValue = new GetExternalDbSystemsExternalDbSystemCollectionItemDatabaseManagementConfig();
            _resultValue.licenseModel = licenseModel;
            return _resultValue;
        }
    }
}
