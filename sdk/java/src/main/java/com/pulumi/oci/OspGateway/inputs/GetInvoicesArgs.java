// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OspGateway.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.OspGateway.inputs.GetInvoicesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetInvoicesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetInvoicesArgs Empty = new GetInvoicesArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetInvoicesFilterArgs>> filters;

    public Optional<Output<List<GetInvoicesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The invoice query param (not unique).
     * 
     */
    @Import(name="invoiceId")
    private @Nullable Output<String> invoiceId;

    /**
     * @return The invoice query param (not unique).
     * 
     */
    public Optional<Output<String>> invoiceId() {
        return Optional.ofNullable(this.invoiceId);
    }

    /**
     * The home region&#39;s public name of the logged in user.
     * 
     */
    @Import(name="ospHomeRegion", required=true)
    private Output<String> ospHomeRegion;

    /**
     * @return The home region&#39;s public name of the logged in user.
     * 
     */
    public Output<String> ospHomeRegion() {
        return this.ospHomeRegion;
    }

    /**
     * A filter to only return resources that match the given value. Looking for partial matches in the following fileds: Invoice No., Reference No. (plan number), Payment Ref, Total Amount(plan number), Balance Due(plan number) and Party/Customer Name
     * 
     */
    @Import(name="searchText")
    private @Nullable Output<String> searchText;

    /**
     * @return A filter to only return resources that match the given value. Looking for partial matches in the following fileds: Invoice No., Reference No. (plan number), Payment Ref, Total Amount(plan number), Balance Due(plan number) and Party/Customer Name
     * 
     */
    public Optional<Output<String>> searchText() {
        return Optional.ofNullable(this.searchText);
    }

    /**
     * A filter to only return resources that match one of the status elements.
     * 
     */
    @Import(name="statuses")
    private @Nullable Output<List<String>> statuses;

    /**
     * @return A filter to only return resources that match one of the status elements.
     * 
     */
    public Optional<Output<List<String>>> statuses() {
        return Optional.ofNullable(this.statuses);
    }

    /**
     * description: End time (UTC) of the target invoice date range for which to fetch invoice data (exclusive).
     * 
     */
    @Import(name="timeInvoiceEnd")
    private @Nullable Output<String> timeInvoiceEnd;

    /**
     * @return description: End time (UTC) of the target invoice date range for which to fetch invoice data (exclusive).
     * 
     */
    public Optional<Output<String>> timeInvoiceEnd() {
        return Optional.ofNullable(this.timeInvoiceEnd);
    }

    /**
     * description: Start time (UTC) of the target invoice date range for which to fetch invoice data (inclusive).
     * 
     */
    @Import(name="timeInvoiceStart")
    private @Nullable Output<String> timeInvoiceStart;

    /**
     * @return description: Start time (UTC) of the target invoice date range for which to fetch invoice data (inclusive).
     * 
     */
    public Optional<Output<String>> timeInvoiceStart() {
        return Optional.ofNullable(this.timeInvoiceStart);
    }

    /**
     * description: End time (UTC) of the target payment date range for which to fetch invoice data (exclusive).
     * 
     */
    @Import(name="timePaymentEnd")
    private @Nullable Output<String> timePaymentEnd;

    /**
     * @return description: End time (UTC) of the target payment date range for which to fetch invoice data (exclusive).
     * 
     */
    public Optional<Output<String>> timePaymentEnd() {
        return Optional.ofNullable(this.timePaymentEnd);
    }

    /**
     * description: Start time (UTC) of the target payment date range for which to fetch invoice data (inclusive).
     * 
     */
    @Import(name="timePaymentStart")
    private @Nullable Output<String> timePaymentStart;

    /**
     * @return description: Start time (UTC) of the target payment date range for which to fetch invoice data (inclusive).
     * 
     */
    public Optional<Output<String>> timePaymentStart() {
        return Optional.ofNullable(this.timePaymentStart);
    }

    /**
     * A filter to only return resources that match the given type exactly.
     * 
     */
    @Import(name="types")
    private @Nullable Output<List<String>> types;

    /**
     * @return A filter to only return resources that match the given type exactly.
     * 
     */
    public Optional<Output<List<String>>> types() {
        return Optional.ofNullable(this.types);
    }

    private GetInvoicesArgs() {}

    private GetInvoicesArgs(GetInvoicesArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.invoiceId = $.invoiceId;
        this.ospHomeRegion = $.ospHomeRegion;
        this.searchText = $.searchText;
        this.statuses = $.statuses;
        this.timeInvoiceEnd = $.timeInvoiceEnd;
        this.timeInvoiceStart = $.timeInvoiceStart;
        this.timePaymentEnd = $.timePaymentEnd;
        this.timePaymentStart = $.timePaymentStart;
        this.types = $.types;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetInvoicesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetInvoicesArgs $;

        public Builder() {
            $ = new GetInvoicesArgs();
        }

        public Builder(GetInvoicesArgs defaults) {
            $ = new GetInvoicesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetInvoicesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetInvoicesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetInvoicesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param invoiceId The invoice query param (not unique).
         * 
         * @return builder
         * 
         */
        public Builder invoiceId(@Nullable Output<String> invoiceId) {
            $.invoiceId = invoiceId;
            return this;
        }

        /**
         * @param invoiceId The invoice query param (not unique).
         * 
         * @return builder
         * 
         */
        public Builder invoiceId(String invoiceId) {
            return invoiceId(Output.of(invoiceId));
        }

        /**
         * @param ospHomeRegion The home region&#39;s public name of the logged in user.
         * 
         * @return builder
         * 
         */
        public Builder ospHomeRegion(Output<String> ospHomeRegion) {
            $.ospHomeRegion = ospHomeRegion;
            return this;
        }

        /**
         * @param ospHomeRegion The home region&#39;s public name of the logged in user.
         * 
         * @return builder
         * 
         */
        public Builder ospHomeRegion(String ospHomeRegion) {
            return ospHomeRegion(Output.of(ospHomeRegion));
        }

        /**
         * @param searchText A filter to only return resources that match the given value. Looking for partial matches in the following fileds: Invoice No., Reference No. (plan number), Payment Ref, Total Amount(plan number), Balance Due(plan number) and Party/Customer Name
         * 
         * @return builder
         * 
         */
        public Builder searchText(@Nullable Output<String> searchText) {
            $.searchText = searchText;
            return this;
        }

        /**
         * @param searchText A filter to only return resources that match the given value. Looking for partial matches in the following fileds: Invoice No., Reference No. (plan number), Payment Ref, Total Amount(plan number), Balance Due(plan number) and Party/Customer Name
         * 
         * @return builder
         * 
         */
        public Builder searchText(String searchText) {
            return searchText(Output.of(searchText));
        }

        /**
         * @param statuses A filter to only return resources that match one of the status elements.
         * 
         * @return builder
         * 
         */
        public Builder statuses(@Nullable Output<List<String>> statuses) {
            $.statuses = statuses;
            return this;
        }

        /**
         * @param statuses A filter to only return resources that match one of the status elements.
         * 
         * @return builder
         * 
         */
        public Builder statuses(List<String> statuses) {
            return statuses(Output.of(statuses));
        }

        /**
         * @param statuses A filter to only return resources that match one of the status elements.
         * 
         * @return builder
         * 
         */
        public Builder statuses(String... statuses) {
            return statuses(List.of(statuses));
        }

        /**
         * @param timeInvoiceEnd description: End time (UTC) of the target invoice date range for which to fetch invoice data (exclusive).
         * 
         * @return builder
         * 
         */
        public Builder timeInvoiceEnd(@Nullable Output<String> timeInvoiceEnd) {
            $.timeInvoiceEnd = timeInvoiceEnd;
            return this;
        }

        /**
         * @param timeInvoiceEnd description: End time (UTC) of the target invoice date range for which to fetch invoice data (exclusive).
         * 
         * @return builder
         * 
         */
        public Builder timeInvoiceEnd(String timeInvoiceEnd) {
            return timeInvoiceEnd(Output.of(timeInvoiceEnd));
        }

        /**
         * @param timeInvoiceStart description: Start time (UTC) of the target invoice date range for which to fetch invoice data (inclusive).
         * 
         * @return builder
         * 
         */
        public Builder timeInvoiceStart(@Nullable Output<String> timeInvoiceStart) {
            $.timeInvoiceStart = timeInvoiceStart;
            return this;
        }

        /**
         * @param timeInvoiceStart description: Start time (UTC) of the target invoice date range for which to fetch invoice data (inclusive).
         * 
         * @return builder
         * 
         */
        public Builder timeInvoiceStart(String timeInvoiceStart) {
            return timeInvoiceStart(Output.of(timeInvoiceStart));
        }

        /**
         * @param timePaymentEnd description: End time (UTC) of the target payment date range for which to fetch invoice data (exclusive).
         * 
         * @return builder
         * 
         */
        public Builder timePaymentEnd(@Nullable Output<String> timePaymentEnd) {
            $.timePaymentEnd = timePaymentEnd;
            return this;
        }

        /**
         * @param timePaymentEnd description: End time (UTC) of the target payment date range for which to fetch invoice data (exclusive).
         * 
         * @return builder
         * 
         */
        public Builder timePaymentEnd(String timePaymentEnd) {
            return timePaymentEnd(Output.of(timePaymentEnd));
        }

        /**
         * @param timePaymentStart description: Start time (UTC) of the target payment date range for which to fetch invoice data (inclusive).
         * 
         * @return builder
         * 
         */
        public Builder timePaymentStart(@Nullable Output<String> timePaymentStart) {
            $.timePaymentStart = timePaymentStart;
            return this;
        }

        /**
         * @param timePaymentStart description: Start time (UTC) of the target payment date range for which to fetch invoice data (inclusive).
         * 
         * @return builder
         * 
         */
        public Builder timePaymentStart(String timePaymentStart) {
            return timePaymentStart(Output.of(timePaymentStart));
        }

        /**
         * @param types A filter to only return resources that match the given type exactly.
         * 
         * @return builder
         * 
         */
        public Builder types(@Nullable Output<List<String>> types) {
            $.types = types;
            return this;
        }

        /**
         * @param types A filter to only return resources that match the given type exactly.
         * 
         * @return builder
         * 
         */
        public Builder types(List<String> types) {
            return types(Output.of(types));
        }

        /**
         * @param types A filter to only return resources that match the given type exactly.
         * 
         * @return builder
         * 
         */
        public Builder types(String... types) {
            return types(List.of(types));
        }

        public GetInvoicesArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.ospHomeRegion = Objects.requireNonNull($.ospHomeRegion, "expected parameter 'ospHomeRegion' to be non-null");
            return $;
        }
    }

}