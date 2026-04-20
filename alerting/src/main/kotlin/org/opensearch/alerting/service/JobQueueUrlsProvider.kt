/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.alerting.service

/**
 * Provides SQS queue URLs for the monitor job poller.
 * Implementation is external to the alerting plugin.
 */
interface JobQueueUrlsProvider {
    fun getQueueUrls(): List<String>
}
