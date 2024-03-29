// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceMesh.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMeshesMeshCollectionItemCertificateAuthority {
    /**
     * @return Unique Mesh identifier.
     * 
     */
    private String id;

    private GetMeshesMeshCollectionItemCertificateAuthority() {}
    /**
     * @return Unique Mesh identifier.
     * 
     */
    public String id() {
        return this.id;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMeshesMeshCollectionItemCertificateAuthority defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String id;
        public Builder() {}
        public Builder(GetMeshesMeshCollectionItemCertificateAuthority defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
        }

        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetMeshesMeshCollectionItemCertificateAuthority", "id");
            }
            this.id = id;
            return this;
        }
        public GetMeshesMeshCollectionItemCertificateAuthority build() {
            final var _resultValue = new GetMeshesMeshCollectionItemCertificateAuthority();
            _resultValue.id = id;
            return _resultValue;
        }
    }
}
