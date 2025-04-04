// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmTraces.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ApmTraces.outputs.GetTraceAggregatedSnapshotDataDetail;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetTraceAggregatedSnapshotDataResult {
    private String apmDomainId;
    /**
     * @return Aggregated snapshot details.
     * 
     */
    private List<GetTraceAggregatedSnapshotDataDetail> details;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private @Nullable String serverName;
    private @Nullable String serviceName;
    private @Nullable String spanKey;
    private @Nullable String spanName;
    private String traceKey;

    private GetTraceAggregatedSnapshotDataResult() {}
    public String apmDomainId() {
        return this.apmDomainId;
    }
    /**
     * @return Aggregated snapshot details.
     * 
     */
    public List<GetTraceAggregatedSnapshotDataDetail> details() {
        return this.details;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<String> serverName() {
        return Optional.ofNullable(this.serverName);
    }
    public Optional<String> serviceName() {
        return Optional.ofNullable(this.serviceName);
    }
    public Optional<String> spanKey() {
        return Optional.ofNullable(this.spanKey);
    }
    public Optional<String> spanName() {
        return Optional.ofNullable(this.spanName);
    }
    public String traceKey() {
        return this.traceKey;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetTraceAggregatedSnapshotDataResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String apmDomainId;
        private List<GetTraceAggregatedSnapshotDataDetail> details;
        private String id;
        private @Nullable String serverName;
        private @Nullable String serviceName;
        private @Nullable String spanKey;
        private @Nullable String spanName;
        private String traceKey;
        public Builder() {}
        public Builder(GetTraceAggregatedSnapshotDataResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.apmDomainId = defaults.apmDomainId;
    	      this.details = defaults.details;
    	      this.id = defaults.id;
    	      this.serverName = defaults.serverName;
    	      this.serviceName = defaults.serviceName;
    	      this.spanKey = defaults.spanKey;
    	      this.spanName = defaults.spanName;
    	      this.traceKey = defaults.traceKey;
        }

        @CustomType.Setter
        public Builder apmDomainId(String apmDomainId) {
            if (apmDomainId == null) {
              throw new MissingRequiredPropertyException("GetTraceAggregatedSnapshotDataResult", "apmDomainId");
            }
            this.apmDomainId = apmDomainId;
            return this;
        }
        @CustomType.Setter
        public Builder details(List<GetTraceAggregatedSnapshotDataDetail> details) {
            if (details == null) {
              throw new MissingRequiredPropertyException("GetTraceAggregatedSnapshotDataResult", "details");
            }
            this.details = details;
            return this;
        }
        public Builder details(GetTraceAggregatedSnapshotDataDetail... details) {
            return details(List.of(details));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetTraceAggregatedSnapshotDataResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder serverName(@Nullable String serverName) {

            this.serverName = serverName;
            return this;
        }
        @CustomType.Setter
        public Builder serviceName(@Nullable String serviceName) {

            this.serviceName = serviceName;
            return this;
        }
        @CustomType.Setter
        public Builder spanKey(@Nullable String spanKey) {

            this.spanKey = spanKey;
            return this;
        }
        @CustomType.Setter
        public Builder spanName(@Nullable String spanName) {

            this.spanName = spanName;
            return this;
        }
        @CustomType.Setter
        public Builder traceKey(String traceKey) {
            if (traceKey == null) {
              throw new MissingRequiredPropertyException("GetTraceAggregatedSnapshotDataResult", "traceKey");
            }
            this.traceKey = traceKey;
            return this;
        }
        public GetTraceAggregatedSnapshotDataResult build() {
            final var _resultValue = new GetTraceAggregatedSnapshotDataResult();
            _resultValue.apmDomainId = apmDomainId;
            _resultValue.details = details;
            _resultValue.id = id;
            _resultValue.serverName = serverName;
            _resultValue.serviceName = serviceName;
            _resultValue.spanKey = spanKey;
            _resultValue.spanName = spanName;
            _resultValue.traceKey = traceKey;
            return _resultValue;
        }
    }
}
