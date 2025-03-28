// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolumeCreateDetailSourceDetail {
    /**
     * @return The OCID of the volume backup.
     * 
     */
    private String id;
    /**
     * @return The type of action to run when the instance is interrupted for eviction.
     * 
     */
    private String type;

    private GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolumeCreateDetailSourceDetail() {}
    /**
     * @return The OCID of the volume backup.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The type of action to run when the instance is interrupted for eviction.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolumeCreateDetailSourceDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String id;
        private String type;
        public Builder() {}
        public Builder(GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolumeCreateDetailSourceDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolumeCreateDetailSourceDetail", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolumeCreateDetailSourceDetail", "type");
            }
            this.type = type;
            return this;
        }
        public GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolumeCreateDetailSourceDetail build() {
            final var _resultValue = new GetInstanceConfigurationsInstanceConfigurationInstanceDetailBlockVolumeCreateDetailSourceDetail();
            _resultValue.id = id;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
