#!/usr/bin/perl

push @INC, '/home.westgrid/lairdm/working/psort/bio-tools-psort-all/lib/';

use strict;
require Bio::Tools::PSort::Module::SVMLocApache;
use Bio::Seq;
use Data::Dumper;

my $url = 'http://control/svmloc';

test_svm($url, 'Cytoplasmic');
test_svm($url, 'Cytoplasmic');
test_svm($url, 'Periplasmic');
test_svm($url, 'Crap');

sub test_svm() {
    my ($url, $module) = @_;

    my $svmloc = new Bio::Tools::PSort::Module::SVMLocApache(-module => $module, -url => $url);

    my $seq = new Bio::Seq( -seq => 'MAKSLFRALVALSFLAPLWLNAAPRVITLSPANTELAFAAGITPVGVSSYSDYPLQAQKIEQVSTWQGMNLERIVALKPDLVIAWRGGNAERQVDQLASLGIKVMWVDATSIEQIANALRQLAPWSPQPDKAEQAAQSLLDQYAQLKAQYADKPKKRVFLQFGINPPFTSGKESIQNQVLEVCGGENIFKDSRVPWPQVSREQVLARSPQAIVITGGPDQIPKIKQYWGEQLKIPVIPLTSDWFERASPRIILAAQQLCNALSQVD');

    my $results = $svmloc->run($seq);

    print Dumper($results) . "\n";

}
