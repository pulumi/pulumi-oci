// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDbSystemsDbSystemIormConfigCachDbPlan {
    private String dbName;
    private String flashCacheLimit;
    private Integer share;

    private GetDbSystemsDbSystemIormConfigCachDbPlan() {}
    public String dbName() {
        return this.dbName;
    }
    public String flashCacheLimit() {
        return this.flashCacheLimit;
    }
    public Integer share() {
        return this.share;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDbSystemsDbSystemIormConfigCachDbPlan defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String dbName;
        private String flashCacheLimit;
        private Integer share;
        public Builder() {}
        public Builder(GetDbSystemsDbSystemIormConfigCachDbPlan defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dbName = defaults.dbName;
    	      this.flashCacheLimit = defaults.flashCacheLimit;
    	      this.share = defaults.share;
        }

        @CustomType.Setter
        public Builder dbName(String dbName) {
            if (dbName == null) {
              throw new MissingRequiredPropertyException("GetDbSystemsDbSystemIormConfigCachDbPlan", "dbName");
            }
            this.dbName = dbName;
            return this;
        }
        @CustomType.Setter
        public Builder flashCacheLimit(String flashCacheLimit) {
            if (flashCacheLimit == null) {
              throw new MissingRequiredPropertyException("GetDbSystemsDbSystemIormConfigCachDbPlan", "flashCacheLimit");
            }
            this.flashCacheLimit = flashCacheLimit;
            return this;
        }
        @CustomType.Setter
        public Builder share(Integer share) {
            if (share == null) {
              throw new MissingRequiredPropertyException("GetDbSystemsDbSystemIormConfigCachDbPlan", "share");
            }
            this.share = share;
            return this;
        }
        public GetDbSystemsDbSystemIormConfigCachDbPlan build() {
            final var _resultValue = new GetDbSystemsDbSystemIormConfigCachDbPlan();
            _resultValue.dbName = dbName;
            _resultValue.flashCacheLimit = flashCacheLimit;
            _resultValue.share = share;
            return _resultValue;
        }
    }
}
