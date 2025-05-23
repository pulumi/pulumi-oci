// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Psql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetBackupSourceBackupDetail {
    /**
     * @return Backup ID of the COPY source type.
     * 
     */
    private String sourceBackupId;
    /**
     * @return Backup Region of the COPY source type.
     * 
     */
    private String sourceRegion;

    private GetBackupSourceBackupDetail() {}
    /**
     * @return Backup ID of the COPY source type.
     * 
     */
    public String sourceBackupId() {
        return this.sourceBackupId;
    }
    /**
     * @return Backup Region of the COPY source type.
     * 
     */
    public String sourceRegion() {
        return this.sourceRegion;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBackupSourceBackupDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String sourceBackupId;
        private String sourceRegion;
        public Builder() {}
        public Builder(GetBackupSourceBackupDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.sourceBackupId = defaults.sourceBackupId;
    	      this.sourceRegion = defaults.sourceRegion;
        }

        @CustomType.Setter
        public Builder sourceBackupId(String sourceBackupId) {
            if (sourceBackupId == null) {
              throw new MissingRequiredPropertyException("GetBackupSourceBackupDetail", "sourceBackupId");
            }
            this.sourceBackupId = sourceBackupId;
            return this;
        }
        @CustomType.Setter
        public Builder sourceRegion(String sourceRegion) {
            if (sourceRegion == null) {
              throw new MissingRequiredPropertyException("GetBackupSourceBackupDetail", "sourceRegion");
            }
            this.sourceRegion = sourceRegion;
            return this;
        }
        public GetBackupSourceBackupDetail build() {
            final var _resultValue = new GetBackupSourceBackupDetail();
            _resultValue.sourceBackupId = sourceBackupId;
            _resultValue.sourceRegion = sourceRegion;
            return _resultValue;
        }
    }
}
