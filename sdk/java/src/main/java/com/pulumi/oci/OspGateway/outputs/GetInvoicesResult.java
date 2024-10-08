// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OspGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OspGateway.outputs.GetInvoicesFilter;
import com.pulumi.oci.OspGateway.outputs.GetInvoicesInvoiceCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetInvoicesResult {
    private String compartmentId;
    private @Nullable List<GetInvoicesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of invoice_collection.
     * 
     */
    private List<GetInvoicesInvoiceCollection> invoiceCollections;
    /**
     * @return Invoice identifier which is generated on the on-premise sie. Pls note this is not an OCID
     * 
     */
    private @Nullable String invoiceId;
    private String ospHomeRegion;
    private @Nullable String searchText;
    private @Nullable List<String> statuses;
    private @Nullable String timeInvoiceEnd;
    private @Nullable String timeInvoiceStart;
    private @Nullable String timePaymentEnd;
    private @Nullable String timePaymentStart;
    private @Nullable List<String> types;

    private GetInvoicesResult() {}
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetInvoicesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The list of invoice_collection.
     * 
     */
    public List<GetInvoicesInvoiceCollection> invoiceCollections() {
        return this.invoiceCollections;
    }
    /**
     * @return Invoice identifier which is generated on the on-premise sie. Pls note this is not an OCID
     * 
     */
    public Optional<String> invoiceId() {
        return Optional.ofNullable(this.invoiceId);
    }
    public String ospHomeRegion() {
        return this.ospHomeRegion;
    }
    public Optional<String> searchText() {
        return Optional.ofNullable(this.searchText);
    }
    public List<String> statuses() {
        return this.statuses == null ? List.of() : this.statuses;
    }
    public Optional<String> timeInvoiceEnd() {
        return Optional.ofNullable(this.timeInvoiceEnd);
    }
    public Optional<String> timeInvoiceStart() {
        return Optional.ofNullable(this.timeInvoiceStart);
    }
    public Optional<String> timePaymentEnd() {
        return Optional.ofNullable(this.timePaymentEnd);
    }
    public Optional<String> timePaymentStart() {
        return Optional.ofNullable(this.timePaymentStart);
    }
    public List<String> types() {
        return this.types == null ? List.of() : this.types;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInvoicesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetInvoicesFilter> filters;
        private String id;
        private List<GetInvoicesInvoiceCollection> invoiceCollections;
        private @Nullable String invoiceId;
        private String ospHomeRegion;
        private @Nullable String searchText;
        private @Nullable List<String> statuses;
        private @Nullable String timeInvoiceEnd;
        private @Nullable String timeInvoiceStart;
        private @Nullable String timePaymentEnd;
        private @Nullable String timePaymentStart;
        private @Nullable List<String> types;
        public Builder() {}
        public Builder(GetInvoicesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.invoiceCollections = defaults.invoiceCollections;
    	      this.invoiceId = defaults.invoiceId;
    	      this.ospHomeRegion = defaults.ospHomeRegion;
    	      this.searchText = defaults.searchText;
    	      this.statuses = defaults.statuses;
    	      this.timeInvoiceEnd = defaults.timeInvoiceEnd;
    	      this.timeInvoiceStart = defaults.timeInvoiceStart;
    	      this.timePaymentEnd = defaults.timePaymentEnd;
    	      this.timePaymentStart = defaults.timePaymentStart;
    	      this.types = defaults.types;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetInvoicesResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetInvoicesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetInvoicesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetInvoicesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder invoiceCollections(List<GetInvoicesInvoiceCollection> invoiceCollections) {
            if (invoiceCollections == null) {
              throw new MissingRequiredPropertyException("GetInvoicesResult", "invoiceCollections");
            }
            this.invoiceCollections = invoiceCollections;
            return this;
        }
        public Builder invoiceCollections(GetInvoicesInvoiceCollection... invoiceCollections) {
            return invoiceCollections(List.of(invoiceCollections));
        }
        @CustomType.Setter
        public Builder invoiceId(@Nullable String invoiceId) {

            this.invoiceId = invoiceId;
            return this;
        }
        @CustomType.Setter
        public Builder ospHomeRegion(String ospHomeRegion) {
            if (ospHomeRegion == null) {
              throw new MissingRequiredPropertyException("GetInvoicesResult", "ospHomeRegion");
            }
            this.ospHomeRegion = ospHomeRegion;
            return this;
        }
        @CustomType.Setter
        public Builder searchText(@Nullable String searchText) {

            this.searchText = searchText;
            return this;
        }
        @CustomType.Setter
        public Builder statuses(@Nullable List<String> statuses) {

            this.statuses = statuses;
            return this;
        }
        public Builder statuses(String... statuses) {
            return statuses(List.of(statuses));
        }
        @CustomType.Setter
        public Builder timeInvoiceEnd(@Nullable String timeInvoiceEnd) {

            this.timeInvoiceEnd = timeInvoiceEnd;
            return this;
        }
        @CustomType.Setter
        public Builder timeInvoiceStart(@Nullable String timeInvoiceStart) {

            this.timeInvoiceStart = timeInvoiceStart;
            return this;
        }
        @CustomType.Setter
        public Builder timePaymentEnd(@Nullable String timePaymentEnd) {

            this.timePaymentEnd = timePaymentEnd;
            return this;
        }
        @CustomType.Setter
        public Builder timePaymentStart(@Nullable String timePaymentStart) {

            this.timePaymentStart = timePaymentStart;
            return this;
        }
        @CustomType.Setter
        public Builder types(@Nullable List<String> types) {

            this.types = types;
            return this;
        }
        public Builder types(String... types) {
            return types(List.of(types));
        }
        public GetInvoicesResult build() {
            final var _resultValue = new GetInvoicesResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.invoiceCollections = invoiceCollections;
            _resultValue.invoiceId = invoiceId;
            _resultValue.ospHomeRegion = ospHomeRegion;
            _resultValue.searchText = searchText;
            _resultValue.statuses = statuses;
            _resultValue.timeInvoiceEnd = timeInvoiceEnd;
            _resultValue.timeInvoiceStart = timeInvoiceStart;
            _resultValue.timePaymentEnd = timePaymentEnd;
            _resultValue.timePaymentStart = timePaymentStart;
            _resultValue.types = types;
            return _resultValue;
        }
    }
}
