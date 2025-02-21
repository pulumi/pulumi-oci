// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMysqlDbSystemPointInTimeRecoveryDetail {
    /**
     * @return Earliest recovery time point for the DB System, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     * 
     */
    private String timeEarliestRecoveryPoint;
    /**
     * @return Latest recovery time point for the DB System, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     * 
     */
    private String timeLatestRecoveryPoint;

    private GetMysqlDbSystemPointInTimeRecoveryDetail() {}
    /**
     * @return Earliest recovery time point for the DB System, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     * 
     */
    public String timeEarliestRecoveryPoint() {
        return this.timeEarliestRecoveryPoint;
    }
    /**
     * @return Latest recovery time point for the DB System, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     * 
     */
    public String timeLatestRecoveryPoint() {
        return this.timeLatestRecoveryPoint;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMysqlDbSystemPointInTimeRecoveryDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String timeEarliestRecoveryPoint;
        private String timeLatestRecoveryPoint;
        public Builder() {}
        public Builder(GetMysqlDbSystemPointInTimeRecoveryDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.timeEarliestRecoveryPoint = defaults.timeEarliestRecoveryPoint;
    	      this.timeLatestRecoveryPoint = defaults.timeLatestRecoveryPoint;
        }

        @CustomType.Setter
        public Builder timeEarliestRecoveryPoint(String timeEarliestRecoveryPoint) {
            if (timeEarliestRecoveryPoint == null) {
              throw new MissingRequiredPropertyException("GetMysqlDbSystemPointInTimeRecoveryDetail", "timeEarliestRecoveryPoint");
            }
            this.timeEarliestRecoveryPoint = timeEarliestRecoveryPoint;
            return this;
        }
        @CustomType.Setter
        public Builder timeLatestRecoveryPoint(String timeLatestRecoveryPoint) {
            if (timeLatestRecoveryPoint == null) {
              throw new MissingRequiredPropertyException("GetMysqlDbSystemPointInTimeRecoveryDetail", "timeLatestRecoveryPoint");
            }
            this.timeLatestRecoveryPoint = timeLatestRecoveryPoint;
            return this;
        }
        public GetMysqlDbSystemPointInTimeRecoveryDetail build() {
            final var _resultValue = new GetMysqlDbSystemPointInTimeRecoveryDetail();
            _resultValue.timeEarliestRecoveryPoint = timeEarliestRecoveryPoint;
            _resultValue.timeLatestRecoveryPoint = timeLatestRecoveryPoint;
            return _resultValue;
        }
    }
}
