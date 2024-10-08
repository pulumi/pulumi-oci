// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.util.Objects;

@CustomType
public final class GetPluggableDatabasesPluggableDatabasePdbCreationTypeDetailRefreshableCloneDetail {
    /**
     * @return Indicates whether the Pluggable Database is a refreshable clone.
     * 
     */
    private Boolean isRefreshableClone;

    private GetPluggableDatabasesPluggableDatabasePdbCreationTypeDetailRefreshableCloneDetail() {}
    /**
     * @return Indicates whether the Pluggable Database is a refreshable clone.
     * 
     */
    public Boolean isRefreshableClone() {
        return this.isRefreshableClone;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPluggableDatabasesPluggableDatabasePdbCreationTypeDetailRefreshableCloneDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean isRefreshableClone;
        public Builder() {}
        public Builder(GetPluggableDatabasesPluggableDatabasePdbCreationTypeDetailRefreshableCloneDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isRefreshableClone = defaults.isRefreshableClone;
        }

        @CustomType.Setter
        public Builder isRefreshableClone(Boolean isRefreshableClone) {
            if (isRefreshableClone == null) {
              throw new MissingRequiredPropertyException("GetPluggableDatabasesPluggableDatabasePdbCreationTypeDetailRefreshableCloneDetail", "isRefreshableClone");
            }
            this.isRefreshableClone = isRefreshableClone;
            return this;
        }
        public GetPluggableDatabasesPluggableDatabasePdbCreationTypeDetailRefreshableCloneDetail build() {
            final var _resultValue = new GetPluggableDatabasesPluggableDatabasePdbCreationTypeDetailRefreshableCloneDetail();
            _resultValue.isRefreshableClone = isRefreshableClone;
            return _resultValue;
        }
    }
}
